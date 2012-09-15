/* ==========================================================================
 * thread.c - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012  William Ahern
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
#include <errno.h>

#include <sys/uio.h>
#include <sys/socket.h>

#include <pthread.h>

#include "cqueues.h"


struct cthread {
	int refs, error;
	pthread_t id;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_attr_t attr;

	jmp_buf trap;

	int pipe[2];

	struct {
		struct iovec arg[32];
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

static int atpanic_trap() {
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

	luaL_loadbuffer(L, ct->tmp.arg[0].iov_base, ct->tmp.arg[0].iov_len, "[thread enter]");

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

	for (struct iovec *arg = &ct->tmp.arg[1]; arg < &ct->tmp.arg[ct->tmp.argc]; arg++)
		lua_pushlstring(L, arg->iov_base, arg->iov_len);

	pthread_mutex_unlock(&ct->mutex);
	pthread_cond_signal(&ct->cond);

	if ((error = _setjmp(ct->trap))) {
		ct->error = error;
		goto close;
	}

	lua_pcall(L, 2 + ct->tmp.argc - 1, 0, 0);
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

	for (int index = 1, top = lua_gettop(L) - 1; index <= top; index++) {
		struct iovec *arg = &ct->tmp.arg[ct->tmp.argc];

		if (arg >= endof(ct->tmp.arg)) {
			error = E2BIG;
			goto error;
		}

		arg->iov_base = (char *)luaL_checklstring(L, index, &arg->iov_len);

		ct->tmp.argc++;
	}

	if (0 != cqs_socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, ct->tmp.fd, O_NONBLOCK|O_CLOEXEC))
		goto syerr;

	if ((error = cqs_socket_fdopen(L, ct->tmp.fd[0], NULL)))
		goto error;

	ct->tmp.fd[0] = -1;

	pthread_mutex_lock(&ct->mutex);

	if (!(error = pthread_create(&ct->id, &ct->attr, &ct_enter, ct)))
		pthread_cond_wait(&ct->cond, &ct->mutex);

	pthread_mutex_unlock(&ct->mutex);

	if (error)
		goto error;

	return 2;
syerr:
	error = errno;
error:
	return luaL_error(L, "thread.start: %s", strerror(error));
} /* ct_start() */


static int ct_join(lua_State *L) {
	struct cthread *ct = ct_checkthread(L, 1);
	int error;

	if (pthread_equal(ct->id, pthread_self()))
		return luaL_error(L, "thread.join: cannot join self");

	if (0 == read(ct->pipe[0], &(char){ 0 }, 1)) {
		lua_pushboolean(L, 1);
		lua_pushnil(L); /* FIXME: Push any error code/string */

		return 2;
	} else {
		lua_pushboolean(L, 0);

		return 1;
	}
} /* ct_join() */


static int ct_pollfd(lua_State *L) {
	struct cthread *ct = ct_checkthread(L, 1);

	lua_pushinteger(L, ct->pipe[0]);

	return 1;
} /* ct_pollfd() */


static int ct_events(lua_State *L) {
	struct cthread *ct = ct_checkthread(L, 1);

	lua_pushliteral(L, "r");

	return 1;
} /* ct_events() */


static int ct__gc(lua_State *L) {
	struct cthread **ud = luaL_checkudata(L, 1, CQS_THREAD);

	ct_release(*ud);
	*ud = NULL;

	return 0;
} /* ct__gc() */


static int ct_self(lua_State *L) {
	lua_rawgetp(L, LUA_REGISTRYINDEX, &selfindex);

	return 1;
} /* ct_self() */


static const luaL_Reg ct_methods[] = {
	{ "join",   &ct_join },
	{ "pollfd", &ct_pollfd },
	{ "events", &ct_events },
	{ NULL,     NULL }
};


static const luaL_Reg ct_metamethods[] = {
	{ "__gc", &ct__gc },
	{ NULL,   NULL }
};


static const luaL_Reg ct_globals[] = {
	{ "start", &ct_start },
	{ "self",  &ct_self },
	{ NULL,    NULL }
};

int luaopen__cqueues_thread(lua_State *L) {
	cqs_addclass(L, CQS_THREAD, ct_methods, ct_metamethods);

	luaL_newlib(L, ct_globals);

	return 1;
} /* luaopen__cqueues_thread() */

