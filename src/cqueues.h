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

#include <signal.h>	/* sigset_t */

#include <errno.h>	/* EINTR */

#include <sys/types.h>
#include <sys/socket.h>	/* socketpair(2) */

#include <unistd.h>	/* close(2) pipe(2) */
#include <fcntl.h>	/* fcntl(2) */

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM < 502
#include "compat52.h"
#endif


/*
 * F E A T U R E / E N V I R O N M E N T  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define HAVE_EPOLL  (__linux)
#define HAVE_PORTS  (__sun)
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
#define CQS_NOTIFY "CQS Notify"
#define CQS_CONDITION "CQS Condition"


cqs_nargs_t luaopen__cqueues(lua_State *);

cqs_nargs_t luaopen__cqueues_errno(lua_State *);

cqs_nargs_t luaopen__cqueues_socket(lua_State *);

cqs_nargs_t luaopen__cqueues_signal(lua_State *);

cqs_nargs_t luaopen__cqueues_thread(lua_State *);

cqs_nargs_t luaopen__cqueues_notify(lua_State *);

cqs_nargs_t luaopen__cqueues_condition(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_record(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_packet(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_config(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_hosts(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_hints(lua_State *);

cqs_nargs_t luaopen__cqueues_dns_resolver(lua_State *);

cqs_nargs_t luaopen__cqueues_dns(lua_State *);


void cqs_cancelfd(lua_State *, int);


struct so_options;

cqs_error_t cqs_socket_fdopen(lua_State *, int, const struct so_options *);


static void cqs_requiref(lua_State *L, const char *modname, lua_CFunction openf, int glb) {
	luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED");
	lua_getfield(L, -1, modname);
	lua_remove(L, -2);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		luaL_requiref(L, modname, openf, glb);
	}
} /* cqs_requiref() */


static void cqs_openlibs(lua_State *L) {
	int top = lua_gettop(L);

	cqs_requiref(L, "_cqueues", &luaopen__cqueues, 0);
	cqs_requiref(L, "_cqueues.errno", &luaopen__cqueues_errno, 0);
	cqs_requiref(L, "_cqueues.socket", &luaopen__cqueues_socket, 0);
	cqs_requiref(L, "_cqueues.signal", &luaopen__cqueues_signal, 0);
	cqs_requiref(L, "_cqueues.thread", &luaopen__cqueues_thread, 0);
	cqs_requiref(L, "_cqueues.notify", &luaopen__cqueues_notify, 0);
#if 0 /* Make optional? */
	cqs_requiref(L, "_cqueues.condition", &luaopen__cqueues_condition, 0);
	cqs_requiref(L, "_cqueues.dns.record", &luaopen__cqueues_dns_record, 0);
	cqs_requiref(L, "_cqueues.dns.packet", &luaopen__cqueues_dns_packet, 0);
	cqs_requiref(L, "_cqueues.dns.config", &luaopen__cqueues_dns_config, 0);
	cqs_requiref(L, "_cqueues.dns.hosts", &luaopen__cqueues_dns_hosts, 0);
	cqs_requiref(L, "_cqueues.dns.hints", &luaopen__cqueues_dns_hints, 0);
	cqs_requiref(L, "_cqueues.dns.resolver", &luaopen__cqueues_dns_resolver, 0);
	cqs_requiref(L, "_cqueues.dns", &luaopen__cqueues_dns, 0);
#endif

	lua_settop(L, top);
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


static inline void cqs_addclass(lua_State *L, const char *name, const luaL_Reg *methods, const luaL_Reg *metamethods) {
	if (luaL_newmetatable(L, name)) {
		luaL_setfuncs(L, metamethods, 0);
		lua_newtable(L);
		luaL_setfuncs(L, methods, 0);
		lua_setfield(L, -2, "__index");
		lua_pop(L, 1);
	}
} /* cqs_addclass() */


struct cqs_macro { const char *name; int value; };

static inline void cqs_addmacros(lua_State *L, int index, const struct cqs_macro *macro, size_t count, _Bool swap) {
	index = lua_absindex(L, index);

	for (unsigned i = 0; i < count; i++) {
		lua_pushstring(L, macro[i].name);
		lua_pushinteger(L, macro[i].value);
		lua_rawset(L, index);
	}

	if (!swap)
		return;

	for (unsigned i = 0; i < count; i++) {
		lua_pushinteger(L, macro[i].value);
		lua_pushstring(L, macro[i].name);
		lua_rawset(L, index);
	}
} /* cqs_addmacros() */


static inline void cqs_closefd(int *fd) {
	if (*fd != -1) {
		while (0 != close(*fd) && errno == EINTR)
			;;
		*fd = -1;
	}
} /* cqs_closefd() */


#if !defined O_CLOEXEC
#if __NetBSD__ /* bad hack for NetBSD < 6.0 until we refactor flags code */
#define O_CLOEXEC 0x00400000
#endif
#endif

static inline int cqs_setfd(int fd, int flags) {
	if (flags & O_NONBLOCK) {
		int oflags = fcntl(fd, F_GETFL);
		if (-1 == oflags || -1 == fcntl(fd, F_SETFL, oflags|O_NONBLOCK))
			return errno;
	}

	if (flags & O_CLOEXEC) {
		if (-1 == fcntl(fd, F_SETFD, FD_CLOEXEC))
			return errno;
	}

	return 0;
} /* cqs_setfd() */


static inline int cqs_pipe(int fd[2], int flags) {
#if __linux
	if (0 != pipe2(fd, flags))
		return errno;

	return 0;
#else
	int error;

	if (0 != pipe(fd))
		return errno;

	if ((error = cqs_setfd(fd[0], flags)) || (error = cqs_setfd(fd[1], flags)))
		return error;

	return 0;
#endif
} /* cqs_pipe() */


static inline int cqs_socketpair(int family, int type, int proto, int fd[2], int flags) {
#if defined SOCK_NONBLOCK && defined SOCK_CLOEXEC
	if (flags & O_NONBLOCK)
		type |= SOCK_NONBLOCK;
	if (flags & O_CLOEXEC)
		type |= SOCK_CLOEXEC;

	if (0 != socketpair(family, type, proto, fd))
		return errno;

	return 0;
#else
	int error;

	if (0 != socketpair(family, type, proto, fd))
		return errno;

	if ((error = cqs_setfd(fd[0], flags)) || (error = cqs_setfd(fd[1], flags)))
		return error;

	return 0;
#endif
} /* cqs_pipe2() */


cqs_error_t cqs_sigmask(int, const sigset_t *, sigset_t *);


/*
 * A U X I L L A R Y  R O U T I N E S
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


typedef int cqs_ref_t;

static inline void cqs_unref(lua_State *L, cqs_ref_t *ref) {
	if (*ref != LUA_NOREF) {
		luaL_unref(L, LUA_REGISTRYINDEX, *ref);
		*ref = LUA_NOREF;
	}
} /* cqs_unref() */

static inline void cqs_ref(lua_State *L, cqs_ref_t *ref) {
	cqs_unref(L, ref);
	*ref = luaL_ref(L, LUA_REGISTRYINDEX);
} /* cqs_ref() */

static inline void cqs_getref(lua_State *L, cqs_ref_t ref) {
	if (ref != LUA_NOREF)
		lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
	else
		lua_pushnil(L);
} /* cqs_getref() */


/*
 * D E B U G  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !defined SAY
#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")
#endif


#include <string.h>

#include <sys/stat.h>
#include <sys/ioctl.h>

#if __sun
#include <sys/filio.h>
#include <stropts.h>
#endif

static void cqs_debugfd(int fd) {
	struct stat st;
	char descr[64] = "";
	int pending = -1;

	if (0 != fstat(fd, &st))
		goto syerr;

	if (S_ISSOCK(st.st_mode)) {
		int type;

		if (0 != getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &(socklen_t){ sizeof type }))
			goto syerr;

		if (type == SOCK_STREAM)
			strncat(descr, "stream socket", sizeof descr - 1);
		else if (type == SOCK_DGRAM)
			strncat(descr, "dgram socket", sizeof descr - 1);
		else
			strncat(descr, "other socket", sizeof descr - 1);
	} else {
		if (S_ISFIFO(st.st_mode))
			strncat(descr, "fifo file", sizeof descr - 1);
		else if (S_ISREG(st.st_mode))
			strncat(descr, "regular file", sizeof descr - 1);
		else
			strncat(descr, "other file", sizeof descr - 1);
	}

	ioctl(fd, FIONREAD, &pending);

	SAY("%d: %s (pending:%d)", fd, descr, pending);

	return;
syerr:
	SAY("%d: %s", fd, strerror(errno));
} /* cqs_debugfd() */


#endif /* CQUEUES_H */
