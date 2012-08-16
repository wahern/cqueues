/* ==========================================================================
 * cqueues.h - Lua Continuation Queues
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
#ifndef CQUEUES_H
#define CQUEUES_H

#include <errno.h>  /* EINTR */

#include <unistd.h> /* close(2) */

#include <lua.h>
#include <lauxlib.h>


/*
 * F E A T U R E / E N V I R O N M E N T  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define HAVE_EPOLL  (__linux)
#define HABE_PORTS  (__sun)
#define HAVE_KQUEUE (__FreeBSD__ || __NetBSD__ || __OpenBSD__ || __APPLE__ || __DragonFly__)

#if __GNUC__
#define NOTUSED __attribute__((unused))
#else
#define NOTUSED
#endif

#if (__GNUC__ == 4 && __GNUC_MINOR__ >= 5) || __GNUC__ > 4 || __clang__
#define NOTREACHED __builtin_unreachable()
#else
#define NOTREACHED (void)0
#endif


/*
 * C L A S S  I N T E R F A C E S / R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define cqs_nargs_t int
#define cqs_error_t int

#define CQS_CQUEUE "Continuation Queue"
#define CQS_SOCKET "CQS Socket"
#define CQS_SIGNAL "CQS Signal"
#define CQS_THREAD "CQS Thread"


cqs_nargs_t luaopen__cqueues(lua_State *);

cqs_nargs_t luaopen__cqueues_socket(lua_State *);

cqs_nargs_t luaopen__cqueues_signal(lua_State *);

cqs_nargs_t luaopen__cqueues_thread(lua_State *);


cqs_error_t cqs_socket_fdopen(lua_State *, int);


static void cqs_openlibs(lua_State *L) {
	int top = lua_gettop(L);

	luaL_requiref(L, "_cqueues", &luaopen__cqueues, 0);
	luaL_requiref(L, "_cqueues.socket", &luaopen__cqueues_socket, 0);
	luaL_requiref(L, "_cqueues.signal", &luaopen__cqueues_signal, 0);
	luaL_requiref(L, "_cqueues.thread", &luaopen__cqueues_thread, 0);

	lua_settop(top);
} /* cqs_openlibs() */


static inline int cqs_interpose(lua_State *L, const char *mt) {
	luaL_getmetatable(L, mt);
	lua_getfield(L, -1, "__index");

	lua_pushvalue(L, -4); /* push method name */
	lua_gettable(L, -2);  /* push old method */

	lua_pushvalue(L, -5); /* push method name */
	lua_pushvalue(L, -5); /* push new method */
	lua_settable(L, -4);  /* replace old method */

	return 1; /* return old method */
} /* cqs_interpose() */


static inline void cqs_closefd(int *fd) {
	if (*fd != -1) {
		while (0 != close(*fd) && errno == EINTR)
			;;
		*fd = -1;
	}
} /* cqs_closefd() */


/*
 * M A C R O  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))
#endif

#ifndef countof
#define countof(a) (sizeof (a) / sizeof *(a))
#endif

#ifndef endof
#define endof(a) (&(a)[countof(a)])
#endif

#endif /* CQUEUES_H */
