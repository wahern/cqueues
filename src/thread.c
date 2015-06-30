/* ==========================================================================
 * thread.c - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012, 2014, 2015  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>

#include <sys/uio.h>
#include <sys/socket.h>

#include <pthread.h>

#include <dlfcn.h>

#include "cqueues.h"
#include "lib/llrb.h"


#if defined EOWNERDEAD
#define CT_EOWNERDEAD EOWNERDEAD
#else
#define CT_EOWNERDEAD EBUSY
#endif

struct cthread_arg {
	int type;
	int iscfunction:1;

	union {
		struct iovec string;
		lua_Number number;
		_Bool boolean;
		void *pointer;
	} v;
}; /* struct cthread_arg */

struct cthread_lib {
	Dl_info info;
	void *ref;

	LLRB_ENTRY(cthread_lib) rbe;
}; /* struct cthread_lib */

struct cthread_handle {
	sig_atomic_t held;

#if HAVE_PTHREAD_MUTEX_ROBUST
	pthread_mutex_t hold;
#endif
}; /* struct cthread_handle */

struct cthread {
	int refs, error, status;
	char *msg;

	pthread_t id;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_attr_t attr;

	jmp_buf trap;

	struct cthread_handle handle;

	int pipe[2];

	LLRB_HEAD(libs, cthread_lib) libs;

	struct {
		struct cthread_arg *arg;
		unsigned argc;
		int fd[2];
	} tmp;
}; /* struct cthread */


static const int selfindex;

static struct {
	pthread_once_t once;
	pthread_key_t key;
	int error;
} atpanic = {
	PTHREAD_ONCE_INIT,
};

static void atpanic_once(void) {
	atpanic.error = pthread_key_create(&atpanic.key, 0);
} /* atpanic_once() */

static int atpanic_trap(lua_State *L NOTUSED) {
	struct cthread *ct;

	if ((ct = pthread_getspecific(atpanic.key)))
		_longjmp(ct->trap, EINVAL);

	return 0;
} /* atpanic_trap() */


static int hdl_init(struct cthread_handle *h) {
#if HAVE_PTHREAD_MUTEX_ROBUST
	pthread_mutexattr_t attr;
	int error;

	h->held = 0;

	if ((error = pthread_mutexattr_init(&attr)))
		return error;

	if ((error = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST)))
		goto error;

	if ((error = pthread_mutex_init(&h->hold, &attr)))
		goto error;

	pthread_mutexattr_destroy(&attr);

	return 0;
error:
	pthread_mutexattr_destroy(&attr);

	return error;
#else
	h->held = 0;

	return 0;
#endif
} /* hdl_init() */

static void hdl_destroy(struct cthread_handle *h) {
#if HAVE_PTHREAD_MUTEX_ROBUST
	pthread_mutex_destroy(&h->hold);
#else
	(void)h;

	return;
#endif
} /* hdl_destroy() */

static int hdl_hold(struct cthread_handle *h) {
#if HAVE_PTHREAD_MUTEX_ROBUST
	int error;

	if ((error = pthread_mutex_lock(&h->hold)))
		return error;
#endif
	h->held = 1;

	return 0;
} /* hdl_hold() */

static _Bool hdl_isheld(struct cthread_handle *h) {
#if HAVE_PTHREAD_MUTEX_ROBUST
	int error;

	switch ((error = pthread_mutex_trylock(&h->hold))) {
	case EBUSY:
		return 1;
	case EOWNERDEAD:
		pthread_mutex_consistent(&h->hold);
		/* FALL THROUGH */
	case 0:
		pthread_mutex_unlock(&h->hold);

		return 0;
	default:
		return 1;
	}
#else
	return h->held;
#endif
} /* hdl_isheld() */


static int lib_cmp(struct cthread_lib *a, struct cthread_lib *b) {
	if ((intptr_t)a->info.dli_fbase < (intptr_t)b->info.dli_fbase)
		return -1;
	if ((intptr_t)a->info.dli_fbase > (intptr_t)b->info.dli_fbase)
		return 1;
	return 0;
} /* lib_cmp() */

LLRB_GENERATE_STATIC(libs, cthread_lib, rbe, lib_cmp)

static int ct_addfunc(struct cthread *ct, lua_CFunction f) {
	struct cthread_lib key, *ent;
	void *ref = NULL;

	if (!dladdr(EXTENSION (void *)f, &key.info))
		goto dlerr;

	if ((ent = LLRB_FIND(libs, &ct->libs, &key)))
		return 0;

	if (!(ref = dlopen(key.info.dli_fname, RTLD_NOW|RTLD_LOCAL)))
		goto dlerr;

	if (!(ent = calloc(1, sizeof *ent)))
		goto syerr;

	ent->info = key.info;
	ent->ref = ref;

	LLRB_INSERT(libs, &ct->libs, ent);

	return 0;
dlerr:
	return -1;
syerr:
	if (ref)
		dlclose(ref);

	return errno;
} /* ct_addfunc() */


static struct cthread *ct_checkthread(lua_State *L, int index) {
	struct cthread **ct = luaL_checkudata(L, index, CQS_THREAD);

	luaL_argcheck(L, *ct, index, CQS_THREAD " expected, got NULL");

	return *ct;
} /* ct_checkthread() */


static void ct_release(struct cthread *ct) {
	_Bool destroy;
	struct cthread_lib *ent, *nxt;

	pthread_mutex_lock(&ct->mutex);
	destroy = !--ct->refs;
	pthread_mutex_unlock(&ct->mutex);

	if (!destroy)
		return;

	hdl_destroy(&ct->handle);

	pthread_attr_destroy(&ct->attr);
	pthread_cond_destroy(&ct->cond);
	pthread_mutex_destroy(&ct->mutex);

	cqs_closefd(&ct->pipe[0]);
	cqs_closefd(&ct->pipe[1]);

	for (ent = LLRB_MIN(libs, &ct->libs); ent; ent = nxt) {
		nxt = LLRB_NEXT(libs, &ct->libs, ent);
		LLRB_REMOVE(libs, &ct->libs, ent);
		dlclose(ent->ref);
		free(ent);
	}

	cqs_closefd(&ct->tmp.fd[0]);
	cqs_closefd(&ct->tmp.fd[1]);

	free(ct->tmp.arg);

	free(ct->msg);
	free(ct);
} /* ct_release() */


static void *ct_enter(void *arg) {
	struct cthread *ct = arg, **ud;
	lua_State *L = NULL;
	int error;

	/*
	 * Hold down deadman switch so ct_join can detect (on some systems)
	 * whether thread was killed or cancelled.
	 */
	hdl_hold(&ct->handle);

	/*
	 * Procedure for bootstrapping into a new Lua VM. Order is important
	 * because arg[0..N] are interned strings from the parent Lua VM.
	 *
	 *  1) Acquire lock.
	 *  -- BEGIN CRITICAL SECTION --
	 *  2) Grab struct cthread reference.
	 *  3) Open new main Lua thread.
	 *  4) Set Lua panic trap.
	 *  5) Load low-level components from memory as we might be
	 *     chroot'd and unable to load them from disk.
	 *  6) Load arg[0] as our Lua start routine.
	 *  7) Push reference to struct cthread.
	 *  8) Push reference to our socket.
	 *  9) Push strings arg[1..N].
	 *  -- END CRITICAL SECTION --
	 * 10) Release lock and signal parent.
	 * 11) Reset Lua panic trap.
	 * 12) Call Lua start routine.
	 *
	 * NOTE: Lua user code perceives this process differently. See
	 * thread.lua.
	 */
	pthread_mutex_lock(&ct->mutex);

	ct->refs++;

	if (!(L = luaL_newstate()))
		goto syerr;

	if ((error = pthread_once(&atpanic.once, &atpanic_once)))
		goto error;

	if ((error = pthread_setspecific(atpanic.key, ct)))
		goto error;

	lua_atpanic(L, &atpanic_trap);

	if ((error = _setjmp(ct->trap)))
		goto error;

	luaL_openlibs(L);
	cqs_openlibs(L);

	if (ct->tmp.arg[0].iscfunction) {
		lua_pushcfunction(L, EXTENSION (lua_CFunction)ct->tmp.arg[0].v.pointer);
	} else {
		luaL_loadbuffer(L, ct->tmp.arg[0].v.string.iov_base, ct->tmp.arg[0].v.string.iov_len, "[thread enter]");
	}

	ud = lua_newuserdata(L, sizeof *ud);
	*ud = NULL;

	luaL_getmetatable(L, CQS_THREAD);
	lua_setmetatable(L, -2);

	ct->refs++;
	*ud = ct;

	lua_pushvalue(L, -1);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &selfindex);

	if ((error = cqs_socket_fdopen(L, ct->tmp.fd[1], NULL)))
		goto error;

	ct->tmp.fd[1] = -1;

	for (struct cthread_arg *arg = &ct->tmp.arg[1]; arg < &ct->tmp.arg[ct->tmp.argc]; arg++) {
		switch (arg->type) {
		case LUA_TNUMBER:
			lua_pushnumber(L, arg->v.number);
			break;
		case LUA_TBOOLEAN:
			lua_pushboolean(L, arg->v.boolean);
			break;
		case LUA_TLIGHTUSERDATA:
			lua_pushlightuserdata(L, arg->v.pointer);
			break;
		case LUA_TSTRING:
			lua_pushlstring(L, arg->v.string.iov_base, arg->v.string.iov_len);
			break;
		case LUA_TFUNCTION:
			if (arg->iscfunction) {
				lua_pushcfunction(L, EXTENSION (lua_CFunction)arg->v.pointer);
			} else {
				luaL_loadbuffer(L, arg->v.string.iov_base, arg->v.string.iov_len, NULL);
			}
			break;
		default:
			lua_pushnil(L);
			break;
		}
	}

	free(ct->tmp.arg);
	ct->tmp.arg = NULL;
	ct->tmp.argc = 0;

	pthread_mutex_unlock(&ct->mutex);
	pthread_cond_signal(&ct->cond);

	if ((error = _setjmp(ct->trap))) {
		ct->error = error;
		goto close;
	}

	ct->status = lua_pcall(L, lua_gettop(L) - 1, 0, 0);

	if (ct->status != LUA_OK && lua_isstring(L, -1)) {
		if (!(ct->msg = strdup(lua_tostring(L, -1)))) {
			ct->error = errno;
		}
	}
close:
	if (L) {
		if (!(error = _setjmp(ct->trap))) {
			lua_close(L);
		} else if (!ct->error) {
			ct->error = error;
		}
	}

	cqs_closefd(&ct->pipe[1]);

	ct_release(ct);

	return 0;
syerr:
	error = errno;
error: /* NOTE: Only critical section errors reach here. */
	ct->error = error;

	pthread_mutex_unlock(&ct->mutex);
	pthread_cond_signal(&ct->cond);

	goto close;
} /* ct_enter() */


static int dump_add(lua_State *L NOTUSED, const void *p, size_t sz, void *ud) {
	luaL_addlstring(((luaL_Buffer *)ud), p, sz);
	return 0;
} /* dump_add() */

static int ct_setfarg(lua_State *L, struct cthread *ct, struct cthread_arg *arg, int index) {
	lua_Debug info;
	lua_CFunction f;
	int error;

	lua_pushvalue(L, index);
	lua_getinfo(L, ">u", &info);

	if ((f = lua_tocfunction(L, index))) {
		if (info.nups > 0)
			goto uperr;

		if ((error = ct_addfunc(ct, f))) {
			if (error == -1)
				return luaL_argerror(L, index, dlerror());

			return error;
		}

		arg->v.pointer = EXTENSION (void *)f;
		arg->iscfunction = 1;
	} else {
		lua_State *T;
		luaL_Buffer B;

		/* _ENV is always first upvalue (if any) in Lua 5.2+ */
		if ((LUA_VERSION_NUM < 502 && info.nups > 0) || info.nups > 1)
			goto uperr;

		luaL_checkstack(L, 2, NULL);

		/*
		 * NOTE: Must put luaL_Buffer on a different stack because
		 * luaL_Buffer has stack constraints that lua_dump is not
		 * guaranteed to meet--we don't know if and how lua_dump
		 * will keep intermediate objects on top of the stack.
		 */
		T = lua_newthread(L);
		luaL_buffinit(T, &B);
		lua_pushvalue(L, index);
#if LUA_VERSION_NUM >= 503
		lua_dump(L, &dump_add, &B, 0);
#else
		lua_dump(L, &dump_add, &B);
#endif
		luaL_pushresult(&B);

		arg->v.string.iov_base = (char *)luaL_checklstring(T, -1, &arg->v.string.iov_len);
	}

	arg->type = LUA_TFUNCTION;

	return 0;
uperr:
	return luaL_argerror(L, index, "function has upvalues");
} /* ct_setfarg() */


/* on success destroy object with ct_release(); on failure use free(3) */
static int ct_init(struct cthread *ct) {
	int progress = 0;
	int error;

	ct->refs = 1;

	ct->pipe[0] = -1;
	ct->pipe[1] = -1;

	ct->tmp.fd[0] = -1;
	ct->tmp.fd[1] = -1;

	if ((error = pthread_mutex_init(&ct->mutex, NULL)))
		goto error;

	progress++;

	if ((error = pthread_cond_init(&ct->cond, NULL)))
		goto error;

	progress++;

	if ((error = pthread_attr_init(&ct->attr)))
		goto error;

	progress++;

	if ((error = hdl_init(&ct->handle)))
		goto error;

	progress++;

	return 0;
error:
	switch (progress) {
	case 4:
		hdl_destroy(&ct->handle);
	case 3:
		pthread_attr_destroy(&ct->attr);
	case 2:
		pthread_cond_destroy(&ct->cond);
	case 1:
		pthread_mutex_destroy(&ct->mutex);
	case 0:
		break;
	}

	return error;
} /* ct_init() */

static struct cthread *ct_create(int *_error) {
	struct cthread *ct = NULL;
	int error;

	if (!(ct = calloc(1, sizeof *ct)))
		goto syerr;

	if ((error = ct_init(ct))) {
		free(ct);
		ct = NULL;
		goto error;
	}

	if ((error = pthread_attr_setdetachstate(&ct->attr, PTHREAD_CREATE_DETACHED)))
		goto error;

	if ((error = cqs_pipe(ct->pipe, O_NONBLOCK|O_CLOEXEC)))
		goto error;

	return ct;
syerr:
	error = errno;
error:
	*_error = error;

	ct_release(ct);

	return NULL;
} /* ct_create() */

static int ct_start(lua_State *L) {
	struct cthread **ud, *ct;
	sigset_t mask, omask;
	int top, error;

	top = lua_gettop(L);

	ud = lua_newuserdata(L, sizeof *ud);
	*ud = NULL;

	luaL_getmetatable(L, CQS_THREAD);
	lua_setmetatable(L, -2);

	if (!(ct = *ud = ct_create(&error)))
		goto error;

	luaL_checktype(L, 1, LUA_TFUNCTION);

	if (!(ct->tmp.arg = calloc(sizeof *ct->tmp.arg, top)))
		goto syerr;

	for (int index = 1; index <= top; index++) {
		struct cthread_arg *arg = &ct->tmp.arg[ct->tmp.argc];

		switch (lua_type(L, index)) {
		case LUA_TNIL:
			arg->type = LUA_TNIL;
			break;
		case LUA_TNUMBER:
			arg->v.number = lua_tonumber(L, index);
			arg->type = LUA_TNUMBER;
			break;
		case LUA_TBOOLEAN:
			arg->v.boolean = lua_toboolean(L, index);
			arg->type = LUA_TBOOLEAN;
			break;
		case LUA_TLIGHTUSERDATA:
			arg->v.pointer = lua_touserdata(L, index);
			arg->type = LUA_TLIGHTUSERDATA;
			break;
		case LUA_TFUNCTION:
			if ((error = ct_setfarg(L, ct, arg, index)))
				goto error;
			break;
		default:
			/* FALL THROUGH (maybe has __tostring metamethod) */
		case LUA_TSTRING:
			arg->v.string.iov_base = (char *)luaL_checklstring(L, index, &arg->v.string.iov_len);
			arg->type = LUA_TSTRING;
			break;
		}

		ct->tmp.argc++;
	}

	/* we may have added more stack objects above the thread object */
	luaL_checkstack(L, 2, NULL);
	lua_pushvalue(L, top + 1);

	if (0 != cqs_socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, ct->tmp.fd, O_NONBLOCK|O_CLOEXEC))
		goto syerr;

	if ((error = cqs_socket_fdopen(L, ct->tmp.fd[0], NULL)))
		goto error;

	ct->tmp.fd[0] = -1;

	sigfillset(&mask);
	sigemptyset(&omask);
	if ((error = pthread_sigmask(SIG_SETMASK, &mask, &omask)))
		goto error;

	pthread_mutex_lock(&ct->mutex);

	if (!(error = pthread_create(&ct->id, &ct->attr, &ct_enter, ct)))
		pthread_cond_wait(&ct->cond, &ct->mutex);

	pthread_mutex_unlock(&ct->mutex);

	pthread_sigmask(SIG_SETMASK, &omask, NULL);

	if (error)
		goto error;

	return 2;
syerr:
	error = errno;
error:
	lua_settop(L, 0);

	lua_pushnil(L);
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 3;
} /* ct_start() */


static int ct_join(lua_State *L) {
	struct cthread *ct = ct_checkthread(L, 1);
	int error;

	if (pthread_equal(ct->id, pthread_self()))
		return luaL_error(L, "thread.join: cannot join self");

	if (0 == read(ct->pipe[0], &(char){ 0 }, 1)) {
		lua_pushboolean(L, 1);

		if (ct->error)
			lua_pushinteger(L, ct->error);
		else if (ct->msg)
			lua_pushstring(L, ct->msg);
		else
			lua_pushnil(L);

		return 2;
	} else {
		error = errno;

		if (error == EAGAIN && !hdl_isheld(&ct->handle))
			error = CT_EOWNERDEAD;

		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}
} /* ct_join() */


static int ct_pollfd(lua_State *L) {
	struct cthread *ct = ct_checkthread(L, 1);

	lua_pushinteger(L, ct->pipe[0]);

	return 1;
} /* ct_pollfd() */


static int ct_events(lua_State *L) {
	ct_checkthread(L, 1);

	lua_pushliteral(L, "r");

	return 1;
} /* ct_events() */


static int ct_timeout(lua_State *L) {
	ct_checkthread(L, 1);

	return 0;
} /* ct_timeout() */


static int ct__eq(lua_State *L) {
	struct cthread **a = luaL_testudata(L, 1, CQS_THREAD);
	struct cthread **b = luaL_testudata(L, 2, CQS_THREAD);

	lua_pushboolean(L, a && b && (*a == *b));

	return 1;
} /* ct__eq() */


static int ct__gc(lua_State *L) {
	struct cthread **ud = luaL_checkudata(L, 1, CQS_THREAD);

	ct_release(*ud);
	*ud = NULL;

	return 0;
} /* ct__gc() */


static int ct_type(lua_State *L) {
	if (luaL_testudata(L, 1, CQS_THREAD)) {
		lua_pushstring(L, "thread");
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* ct_type() */


static int ct_interpose(lua_State *L) {
	return cqs_interpose(L, CQS_THREAD);
} /* ct_interpose() */


static int ct_self(lua_State *L) {
	lua_rawgetp(L, LUA_REGISTRYINDEX, &selfindex);

	return 1;
} /* ct_self() */


static const luaL_Reg ct_methods[] = {
	{ "join",    &ct_join },
	{ "pollfd",  &ct_pollfd },
	{ "events",  &ct_events },
	{ "timeout", &ct_timeout },
	{ NULL,      NULL }
};


static const luaL_Reg ct_metamethods[] = {
	{ "__eq", &ct__eq },
	{ "__gc", &ct__gc },
	{ NULL,   NULL }
};


static const luaL_Reg ct_globals[] = {
	{ "start",     &ct_start },
	{ "type",      &ct_type },
	{ "interpose", &ct_interpose },
	{ "self",      &ct_self },
	{ NULL,        NULL }
};


static int ct_protectssl(void);

int luaopen__cqueues_thread(lua_State *L) {
	int error;

	if ((error = ct_protectssl())) {
		if (error == -1) {
			return luaL_error(L, "%s", dlerror());
		} else {
			return luaL_error(L, "%s", cqs_strerror(error));
		}
	}

	cqs_newmetatable(L, CQS_THREAD, ct_methods, ct_metamethods, 0);

	luaL_newlib(L, ct_globals);

	return 1;
} /* luaopen__cqueues_thread() */


/*
 * OpenSSL is not thread-safe without explicit locking handlers installed.
 */
#include <openssl/crypto.h>

static struct {
	pthread_mutex_t *lock;
	int count;
	void *dlref;
} openssl;

static void ct_lockssl(int mode, int type, const char *file NOTUSED, int line NOTUSED) {
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&openssl.lock[type]);
	else
		pthread_mutex_unlock(&openssl.lock[type]);
} /* ct_lockssl() */


/*
 * Sources include Google and especially the Wine Project. See get_unix_tid
 * at http://source.winehq.org/git/wine.git/?a=blob;f=dlls/ntdll/server.c.
 */
#if __FreeBSD__
#include <sys/thr.h> /* thr_self(2) */
#elif __NetBSD__
#include <lwp.h> /* _lwp_self(2) */
#endif

static unsigned long ct_selfid(void) {
#if __APPLE__
	return pthread_mach_thread_np(pthread_self());
#elif __DragonFly__
	return lwp_gettid();
#elif  __FreeBSD__
	long id;

	thr_self(&id);

	return id;
#elif __NetBSD__
	return _lwp_self();
#else
	/*
	 * pthread_t is an integer on Solaris and Linux, and a unique pointer
	 * on OpenBSD.
	 */
	return (unsigned long)pthread_self();
#endif
} /* ct_selfid() */


static int ct_protectssl(void) {
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	int bound = 0, error = 0;

	pthread_mutex_lock(&mutex);

	if (!CRYPTO_get_locking_callback()) {
		if (!openssl.lock) {
			int i;

			openssl.count = CRYPTO_num_locks();

			if (!(openssl.lock = malloc(openssl.count * sizeof *openssl.lock))) {
				error = errno;
				goto leave;
			}

			for (i = 0; i < openssl.count; i++) {
				pthread_mutex_init(&openssl.lock[i], NULL);
			}
		}

		CRYPTO_set_locking_callback(&ct_lockssl);
		bound = 1;
	}

	if (!CRYPTO_get_id_callback()) {
		CRYPTO_set_id_callback(&ct_selfid);
		bound = 1;
	}

	/*
	 * Prevent loader from unlinking us if we've registered a callback
	 * with OpenSSL.
	 */
	if (bound && !openssl.dlref) {
		Dl_info info;

		if (!dladdr(EXTENSION (void *)&luaopen__cqueues_thread, &info)) {
			error = -1;
			goto leave;
		}

		if (!(openssl.dlref = dlopen(info.dli_fname, RTLD_NOW|RTLD_LOCAL))) {
			error = -1;
			goto leave;
		}
	}

leave:
	pthread_mutex_unlock(&mutex);

	return error;
} /* ct_protectssl() */

