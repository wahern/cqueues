/* ==========================================================================
 * cqueues.h - Lua Continuation Queues
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
#ifndef CQUEUES_H
#define CQUEUES_H

#include <signal.h>	/* sigset_t */
#include <errno.h>	/* EOVERFLOW */
#include <assert.h>     /* static_assert */

#include <sys/param.h>  /* __NetBSD_Version__ OpenBSD __FreeBSD__version */
#include <sys/types.h>
#include <sys/socket.h>	/* socketpair(2) */
#include <unistd.h>	/* close(2) pipe(2) */
#include <fcntl.h>	/* F_GETFL F_SETFD F_SETFL FD_CLOEXEC O_NONBLOCK O_CLOEXEC fcntl(2) */

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

#ifndef __has_feature
#define __has_feature(...) 0
#endif

#ifndef __has_extension
#define __has_extension(...) 0
#endif

#ifndef __NetBSD_Prereq__
#define __NetBSD_Prereq__(M, m, p) 0
#endif

#define GNUC_PREREQ(M, m) (defined __GNUC__ && ((__GNUC__ > M) || (__GNUC__ == M && __GNUC_MINOR__ >= m)))

#define NETBSD_PREREQ(M, m) __NetBSD_Prereq__(M, m, 0)

#define FREEBSD_PREREQ(M, m) (defined __FreeBSD_version && __FreeBSD_version >= ((M) * 100000) + ((m) * 1000))

#if defined __GLIBC_PREREQ
#define GLIBC_PREREQ(M, m) (defined __GLIBC__ && __GLIBC_PREREQ(M, m) && !__UCLIBC__)
#else
#define GLIBC_PREREQ(M, m) 0
#endif

#define UCLIBC_PREREQ(M, m, p) (defined __UCLIBC__ && (__UCLIBC_MAJOR__ > M || (__UCLIBC_MAJOR__ == M && __UCLIBC_MINOR__ > m) || (__UCLIBC_MAJOR__ == M && __UCLIBC_MINOR__ == m && __UCLIBC_SUBLEVEL__ >= p)))

#ifndef HAVE_EPOLL
#define HAVE_EPOLL (__linux)
#endif

#ifndef HAVE_PORTS
#define HAVE_PORTS (__sun)
#endif

#ifndef HAVE_KQUEUE
#define HAVE_KQUEUE (__FreeBSD__ || __NetBSD__ || __OpenBSD__ || __APPLE__ || __DragonFly__)
#endif

#ifndef HAVE_EVENTFD
#define HAVE_EVENTFD (__linux && (GLIBC_PREREQ(2, 9) || UCLIBC_PREREQ(0, 9, 33)))
#endif

#if __GNUC__
#define NOTUSED __attribute__((unused))
#define EXTENSION __extension__
#else
#define NOTUSED
#define EXTENSION
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

#define cqs_index_t int  /* for documentation purposes */
#define cqs_nargs_t int  /* "" */
#define cqs_error_t int  /* "" */
#define cqs_status_t int /* "" */

#define CQS_CQUEUE "Continuation Queue"
#define CQS_SOCKET "CQS Socket"
#define CQS_SIGNAL "CQS Signal"
#define CQS_THREAD "CQS Thread"
#define CQS_NOTIFY "CQS Notify"
#define CQS_CONDITION "CQS Condition"

#define CQUEUE__POLL ((void *)&cqueue__poll)
const char *cqueue__poll; // signals multilevel yield

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

int cqs_socket_pollfd(lua_State *, int);

int cqs_socket_events(lua_State *, int);

double cqs_socket_timeout(lua_State *, int);


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
	lua_settop(L, 2);

	luaL_getmetatable(L, mt);
	lua_getfield(L, -1, "__index");

	lua_pushvalue(L, 1); /* push method name */
	lua_gettable(L, -2);  /* push old method */

	lua_pushvalue(L, 1); /* push method name */
	lua_pushvalue(L, 2); /* push new method */
	lua_settable(L, -4);  /* replace old method */

	return 1; /* return old method */
} /* cqs_interpose() */


static inline void cqs_pushnils(lua_State *L, int n) {
	int i;

	luaL_checkstack(L, n, NULL);

	for (i = 0; i < n; i++)
		lua_pushnil(L);
} /* cqs_pushnils() */


static inline int cqs_regcount(const luaL_Reg *l) {
	int i;

	for (i = 0; l[i].func; i++)
		;;

	return i;
} /* cqs_regcount() */


/* create new metatable, capturing upvalues for use by methods and metamethods */
static inline void cqs_newmetatable(lua_State *L, const char *name, const luaL_Reg *methods, const luaL_Reg *metamethods, int nup) {
	int i;

	luaL_newmetatable(L, name);
	for (i = 0; i < nup; i++) /* copy upvalues */
		lua_pushvalue(L, -nup - 1);
	luaL_setfuncs(L, metamethods, nup);

	lua_createtable(L, 0, cqs_regcount(methods));
	for (i = 0; i < nup; i++) /* copy upvalues */
		lua_pushvalue(L, -nup - 2);
	luaL_setfuncs(L, methods, nup);
	lua_setfield(L, -2, "__index");

	for (i = 0; i < nup; i++) /* remove the upvalues */
		lua_remove(L, -2);
} /* cqs_newmetatable() */


/*
 * set the n-th upvalue of every lua_CFunction in the table at tindex to the
 * value at the top of the stack
 */
static inline void cqs_setfuncsupvalue(lua_State *L, int tindex, int n) {
	tindex = lua_absindex(L, tindex);

	lua_pushnil(L);
	while (lua_next(L, tindex)) {
		if (lua_iscfunction(L, -1)) {
			lua_pushvalue(L, -3);
			lua_setupvalue(L, -2, n);
		}

		lua_pop(L, 1); /* pop field value (leaving key) */
	}

	lua_pop(L, 1); /* pop upvalue */
} /* cqs_setfuncsupvalue() */


static inline void cqs_setmetaupvalue(lua_State *L, int tindex, int n) {
	tindex = lua_absindex(L, tindex);

	lua_pushvalue(L, -1);
	cqs_setfuncsupvalue(L, tindex, n);

	lua_getfield(L, tindex, "__index");
	lua_pushvalue(L, -2);
	cqs_setfuncsupvalue(L, -2, n);
	lua_pop(L, 1); /* pop __index */

	lua_pop(L, 1); /* pop upvalue */
} /* cqs_setmetaupvalue() */


/* test metatable against copy at upvalue */
static inline void *cqs_testudata(lua_State *L, int index, int upvalue) {
	void *ud = lua_touserdata(L, index);
	int eq;

	if (!ud || !lua_getmetatable(L, index))
		return NULL;

	eq = lua_rawequal(L, -1, lua_upvalueindex(upvalue));
	lua_pop(L, 1);

	return (eq)? ud : NULL;
} /* cqs_testudata() */


static inline void *cqs_checkudata(lua_State *L, int index, int upvalue, const char *tname) {
	void *ud;

	if (!(ud = cqs_testudata(L, index, upvalue))) {
		index = lua_absindex(L, index);

		luaL_argerror(L, index, lua_pushfstring(L, "%s expected, got %s", tname, luaL_typename(L, index)));

		NOTREACHED;
	}

	return ud;
} /* cqs_checkudata() */


struct cqs_macro { const char *name; int value; };

static inline void cqs_setmacros(lua_State *L, int index, const struct cqs_macro *macro, size_t count, _Bool swap) {
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
} /* cqs_setmacros() */


static inline void cqs_closefd(int *fd) {
	if (*fd != -1) {
#if __APPLE__
		/* Do we need bother with close$NOCANCEL$UNIX2003? */
		extern int close$NOCANCEL(int);
		close$NOCANCEL(*fd);
#else
		close(*fd);
#endif
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
} /* cqs_socketpair() */


#ifndef HAVE_STATIC_ASSERT
#define HAVE_STATIC_ASSERT (defined static_assert)
#endif

#ifndef HAVE__STATIC_ASSERT
#define HAVE__STATIC_ASSERT (GNUC_PREREQ(4, 6) || __has_feature(c_static_assert) || __has_extension(c_static_assert))
#endif

#if HAVE_STATIC_ASSERT
#define cqs_static_assert(cond, msg) static_assert(cond, msg)
#elif HAVE__STATIC_ASSERT
#define cqs_static_assert(cond, msg) EXTENSION _Static_assert(cond, msg)
#else
#define cqs_inline_assert(cond) (sizeof (int[1 - 2*!(cond)]))
#define cqs_static_assert(cond, msg) extern char CQS_XPASTE(assert_, __LINE__)[cqs_inline_assert(cond)]
#endif


cqs_error_t cqs_strerror_r(cqs_error_t, char *, size_t);

/*
 * NB: Compound literals have block scope in C. But g++ creates
 * list-initialized temporaries, which only have expression scope.
 */
#if !__cplusplus
#define cqs_strerror(...) cqs_strerror_(__VA_ARGS__, (char [128]){ 0 }, 128, 0)
#define cqs_strerror_(error, dst, lim, ...) (cqs_strerror)((error), (dst), (lim))
#endif

const char *(cqs_strerror)(cqs_error_t, void *, size_t);


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

#define cqs_ispowerof2(x) (((x) != 0) && (0 == (((x) - 1) & (x))))

#define CQS_PASTE(x, y) x ## y
#define CQS_XPASTE(x, y) CQS_PASTE(x, y)

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


static inline cqs_error_t cqs_addzu(size_t *r, size_t a, size_t b) {
	if (~a < b)
		return EOVERFLOW;

	*r = a + b;

	return 0;
} /* cqs_addzu() */


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

NOTUSED static void cqs_debugfd(int fd) {
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
