/* ==========================================================================
 * signal.c - Lua Continuation Queues
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
#include <string.h>

#include <signal.h>

#include <errno.h>

#if defined _REENTRANT || defined _THREAD_SAFE
#include <pthread.h>
#endif

#include <lua.h>
#include <lauxlib.h>


#undef sigmask

static int sigmask(int how, const sigset_t *set, sigset_t *oset) {
#if defined _REENTRANT || defined _THREAD_SAFE
	return pthread_sigmask(how, set, oset);
#else
	return (0 == sigprocmask(how, set, oset))? 0 : errno;
#endif
} /* sigmask() */


struct signalfd {
	int fd;
}; /* struct signalfd */


static int ls_ignore(lua_State *L) {
	struct sigaction sa;
	int index;
	
	for (index = 1; index <= lua_gettop(L); index++) {
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;

		if (0 != sigaction(luaL_checkint(L, index), &sa, 0))
			return luaL_error(L, "signal.ignore: %s", strerror(errno));
	}

	return 0;
} /* ls_ignore() */


static int ls_default(lua_State *L) {
	struct sigaction sa;
	int index;
	
	for (index = 1; index <= lua_gettop(L); index++) {
		sa.sa_handler = SIG_DFL;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;

		if (0 != sigaction(luaL_checkint(L, index), &sa, 0))
			return luaL_error(L, "signal.default: %s", strerror(errno));
	}

	return 0;
} /* ls_default() */


static int ls_block(lua_State *L) {
	sigset_t set;
	int index, error;

	sigemptyset(&set);

	for (index = 1; index <= lua_gettop(L); index++) {
		sigaddset(&set, luaL_checkint(L, index));
	}

	if ((error = sigmask(SIG_BLOCK, &set, 0)))
		return luaL_error(L, "signal.block: %s", strerror(error));

	return 0;
} /* ls_block() */


static int ls_unblock(lua_State *L) {
	sigset_t set;
	int index, error;

	sigemptyset(&set);

	for (index = 1; index <= lua_gettop(L); index++) {
		sigaddset(&set, luaL_checkint(L, index));
	}

	if ((error = sigmask(SIG_UNBLOCK, &set, 0)))
		return luaL_error(L, "signal.unblock: %s", strerror(error));

	return 0;
} /* ls_unblock() */


static int ls_raise(lua_State *L) {
	int index;

	for (index = 1; index <= lua_gettop(L); index++) {
		raise(luaL_checkint(L, index));
	}

	return 0;
} /* ls_raise() */


static int ls_strsignal(lua_State *L) {
	lua_pushstring(L, strsignal(luaL_checkint(L, 1)));

	return 1;
} /* ls_strsignal() */


static const luaL_Reg ls_globals[] = {
	{ "ignore",    &ls_ignore },
	{ "default",   &ls_default },
	{ "block",     &ls_block },
	{ "unblock",   &ls_unblock },
	{ "raise",     &ls_raise },
	{ "strsignal", &ls_strsignal },
	{ NULL, NULL }
};


int luaopen__cqueues_signal(lua_State *L) {
	static const struct {
		const char *name;
		int value;
	} siglist[] = {
		{ "SIGALRM", SIGALRM },
		{ "SIGCHLD", SIGCHLD },
		{ "SIGHUP",  SIGHUP  },
		{ "SIGINT",  SIGINT  },
		{ "SIGPIPE", SIGPIPE },
		{ "SIGQUIT", SIGQUIT },
		{ "SIGTERM", SIGTERM },
	};
	unsigned i;

	luaL_newlib(L, ls_globals);

	for (i = 0; i < sizeof siglist / sizeof *siglist; i++) {
		lua_pushstring(L, siglist[i].name);
		lua_pushinteger(L, siglist[i].value);
		lua_settable(L, -3);

		lua_pushinteger(L, siglist[i].value);
		lua_pushstring(L, siglist[i].name);
		lua_settable(L, -3);
	}

	return 1;
} /* luaopen__cqueues_signal() */


