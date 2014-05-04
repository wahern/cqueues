/* ==========================================================================
 * thread.c - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012, 2014  William Ahern
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


struct cthread_arg {
	int type;

	union {
		struct iovec string;
		lua_Number number;
		_Bool boolean;
		void *pointer;
	} v;
}; /* struct cthread_arg */


struct cthread {
	int refs, error, status;
	char *msg;

	pthread_t id;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_attr_t attr;

	jmp_buf trap;

	int pipe[2];

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


static struct cthread *ct_checkthread(lua_State *L, int index) {
	struct cthread **ct = luaL_checkudata(L, index, CQS_THREAD);

	luaL_argcheck(L, *ct, index, CQS_THREAD " expected, got NULL");

	return *ct;
} /* ct_checkthread() */


static void ct_release(struct cthread *ct) {
	_Bool destroy;

	pthread_mutex_lock(&ct->mutex);
	destroy = !--ct->refs;
	pthread_mutex_unlock(&ct->mutex);

	if (!destroy)
		return;

	pthread_attr_destroy(&ct->attr);
	pthread_cond_destroy(&ct->cond);
	pthread_mutex_destroy(&ct->mutex);

	cqs_closefd(&ct->pipe[0]);
	cqs_closefd(&ct->pipe[1]);

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

	luaL_loadbuffer(L, ct->tmp.arg[0].v.string.iov_base, ct->tmp.arg[0].v.string.iov_len, "[thread enter]");

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


static int ct_start(lua_State *L) {
	struct cthread **ud, *ct;
	sigset_t mask, omask;
	int top, error;

	if (!(top = lua_gettop(L)))
		return luaL_argerror(L, 1, "expected string, got none");

	ud = lua_newuserdata(L, sizeof *ud);
	*ud = NULL;

	luaL_getmetatable(L, CQS_THREAD);
	lua_setmetatable(L, -2);

	if (!(ct = *ud = malloc(sizeof *ct)))
		goto syerr;

	memset(ct, 0, sizeof *ct);

	ct->refs = 1;

	ct->pipe[0] = -1;
	ct->pipe[1] = -1;

	ct->tmp.fd[0] = -1;
	ct->tmp.fd[1] = -1;

	pthread_mutex_init(&ct->mutex, NULL);
	pthread_cond_init(&ct->cond, NULL);
	pthread_attr_init(&ct->attr);

	if ((error = pthread_attr_setdetachstate(&ct->attr, PTHREAD_CREATE_DETACHED)))
		goto error;

	if ((error = cqs_pipe(ct->pipe, O_NONBLOCK|O_CLOEXEC)))
		goto error;

	for (int i = 0; i < 2; i++) {
		if ((error = cqs_setfd(ct->pipe[i], O_NONBLOCK|O_CLOEXEC)))
			goto error;
	}

	luaL_checktype(L, 1, LUA_TSTRING); /* must be serialized function */

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
		default:
			/* FALL THROUGH (maybe has __tostring metamethod) */ 
		case LUA_TSTRING:
			arg->v.string.iov_base = (char *)luaL_checklstring(L, index, &arg->v.string.iov_len);
			arg->type = LUA_TSTRING;
			break;
		}

		ct->tmp.argc++;
	}

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
			char why[256];

			if (0 != strerror_r(error, why, sizeof why) || *why == '\0')
				return luaL_error(L, "Unknown error: %d", error);

			return luaL_error(L, "%s", why);
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

		if (!dladdr((void *)&luaopen__cqueues_thread, &info)) {
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

