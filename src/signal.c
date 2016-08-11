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
#include "config.h"

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <string.h>
#if HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif
#if HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif
#include <sys/time.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include "cqueues.h"


/*
 * S I G N A L  L I S T E N E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef ENABLE_SIGNALFD
#define ENABLE_SIGNALFD HAVE_SIGNALFD
#endif

#ifndef ENABLE_EVFILT_SIGNAL
#define ENABLE_EVFILT_SIGNAL (ENABLE_KQUEUE && defined EVFILT_SIGNAL)
#endif

#define LSL_CLASS "CQS Signal"

#define SIGNAL_SIGNALFD      0x01
#define SIGNAL_EVFILT_SIGNAL 0x02
#define SIGNAL_SIGTIMEDWAIT  0x04
#define SIGNAL_KQUEUE        0x08
#define SIGNAL_KQUEUE1       0x10

static int signal_features(void) {
	return 0
#if ENABLE_SIGNALFD
	| SIGNAL_SIGNALFD
#endif
#if ENABLE_EVFILT_SIGNAL
	| SIGNAL_EVFILT_SIGNAL
#endif
#if HAVE_SIGTIMEDWAIT
	| SIGNAL_SIGTIMEDWAIT
#endif
#if HAVE_KQUEUE
	| SIGNAL_KQUEUE
#endif
#if HAVE_KQUEUE1
	| SIGNAL_KQUEUE1
#endif
	;
}

static const char *signal_strflag(int flag) {
	static const char *const table[32] = {
		[0] = "signalfd", "EVFILT_SIGNAL", "sigtimedwait",
		      "kqueue", "kqueue1",
	};
	int i = ffs(0xFFFFFFFF & flag);
	return (i)? table[i - 1] : NULL;
}

static int signal_flags(int *flags) {
	while (0xFFFFFFFF & *flags) {
		int flag = 1 << (ffs(0xFFFFFFFF & *flags) - 1);
		*flags &= ~flag;
		if (signal_strflag(flag))
			return flag;
	}

	return 0;
}

struct signalfd {
	int fd;
	sigset_t desired;
	sigset_t polling;
	sigset_t pending;

	double timeout;
}; /* struct signalfd */


static void sfd_preinit(struct signalfd *S) {
	S->fd = -1;

	sigemptyset(&S->desired);
	sigemptyset(&S->polling);
	sigemptyset(&S->pending);

#if ENABLE_SIGNALFD || ENABLE_EVFILT_SIGNAL
	S->timeout = NAN;
#else
	S->timeout = 1.1;
#endif
} /* sfd_preinit() */


static int sfd_init(struct signalfd *S) {
#if ENABLE_SIGNALFD
	if (-1 == (S->fd = signalfd(-1, &S->desired, SFD_NONBLOCK|SFD_CLOEXEC)))
		return errno;

	S->polling = S->desired;

	return 0;
#elif ENABLE_EVFILT_SIGNAL
	if (-1 == (S->fd = kqueue()))
		return errno;

	return 0;
#else
	(void)S;
	return 0;
#endif
} /* sfd_init() */


static void sfd_destroy(struct signalfd *S) {
	cqs_closefd(&S->fd);

	sfd_preinit(S);
} /* sfd_destroy() */


static int sfd_diff(const sigset_t *a, const sigset_t *b) {
	for (int signo = 1; signo < 32; signo++) {
		if (!!sigismember(a, signo) ^ !!sigismember(b, signo))
			return signo;
	}

	return 0;
} /* sfd_diff() */


static int sfd_update(struct signalfd *S) {
#if ENABLE_SIGNALFD
	if (sfd_diff(&S->desired, &S->polling)) {
		if (-1 == signalfd(S->fd, &S->desired, 0))
			return errno;

		S->polling = S->desired;
	}

	return 0;
#elif ENABLE_EVFILT_SIGNAL
	int signo;

	while ((signo = sfd_diff(&S->desired, &S->polling))) {
		struct kevent event;

		if (sigismember(&S->desired, signo)) {
			EV_SET(&event, signo, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);

			if (0 != kevent(S->fd, &event, 1, 0, 0, 0))
				return errno;

			sigaddset(&S->polling, signo);
		} else {
			EV_SET(&event, signo, EVFILT_SIGNAL, EV_DELETE, 0, 0, 0);

			if (0 != kevent(S->fd, &event, 1, 0, 0, 0))
				return errno;

			sigdelset(&S->polling, signo);
		}
	}

	return 0;
#else
	(void)S;
	return 0;
#endif
} /* sfd_update() */


static int sfd_query(struct signalfd *S) {
#if ENABLE_SIGNALFD
	struct signalfd_siginfo info;
	long n;

retry:
	if ((n = read(S->fd, &info, sizeof info)) > 0) {
		sigaddset(&S->pending, info.ssi_signo);
	} else if (n == -1) {
		goto syerr;
	}

	return 0;
syerr:
	switch (errno) {
	case EAGAIN:
		return 0;
	case EINTR:
		goto retry;
	default:
		break;
	}

	return errno;
#elif ENABLE_EVFILT_SIGNAL
	struct kevent event;
	int n;

retry:
	if (1 == (n = kevent(S->fd, 0, 0, &event, 1, &(struct timespec){ 0, 0 }))) {
		if (event.filter == EVFILT_SIGNAL) {
			sigaddset(&S->pending, event.ident);
			sigdelset(&S->polling, event.ident);
		}
	} else if (n == -1) {
		if (errno == EINTR)
			goto retry;

		return errno;
	}

	return sfd_update(S);
#elif HAVE_SIGTIMEDWAIT
	int signo;

	if (-1 != (signo = sigtimedwait(&S->desired, NULL, &(struct timespec){ 0, 0 })))
		sigaddset(&S->pending, signo);

	return 0;
#else
	(void)S;
	return EOPNOTSUPP;
#endif
} /* sfd_query() */


static int lsl_listen(lua_State *L) {
	struct signalfd *S;
	int index, error;

	S = lua_newuserdata(L, sizeof *S);

	sfd_preinit(S);

	for (index = 1; index <= lua_gettop(L) - 1; index++)
		sigaddset(&S->desired, luaL_checkint(L, index));

	luaL_getmetatable(L, LSL_CLASS);
	lua_setmetatable(L, -2);

	if ((error = sfd_init(S)) || (error = sfd_update(S)))
		return luaL_error(L, "signal.listen: %s", cqs_strerror(error));

	return 1;
} /* lsl_listen() */


static int lsl__gc(lua_State *L) {
	struct signalfd *S = luaL_checkudata(L, 1, LSL_CLASS);

	sfd_destroy(S);

	return 0;
} /* lsl__gc() */


static int lsl_wait(lua_State *L) {
	struct signalfd *S = luaL_checkudata(L, 1, LSL_CLASS);
	sigset_t none;
	int error, signo;

	if ((error = sfd_query(S)))
		return luaL_error(L, "signal:get: %s", cqs_strerror(error));

	sigemptyset(&none);

	if ((signo = sfd_diff(&S->pending, &none))) {
		lua_pushinteger(L, signo);
		sigdelset(&S->pending, signo);

		return 1;
	}

	return 0;
} /* lsl_wait() */


static int lsl_pollfd(lua_State *L) {
	struct signalfd *S = luaL_checkudata(L, 1, LSL_CLASS);

	lua_pushinteger(L, S->fd);

	return 1;
} /* lsl_pollfd() */


static int lsl_events(lua_State *L) {
	luaL_checkudata(L, 1, LSL_CLASS);

	lua_pushliteral(L, "r");

	return 1;
} /* lsl_events() */


static int lsl_timeout(lua_State *L) {
	struct signalfd *S = luaL_checkudata(L, 1, LSL_CLASS);
	sigset_t none;

	sigemptyset(&none);

	if (sfd_diff(&S->pending, &none)) {
		lua_pushnumber(L, 0.0);
	} else if (isnormal(S->timeout) && !signbit(S->timeout)) {
		lua_pushnumber(L, S->timeout);
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* lsl_timeout() */


static int lsl_settimeout(lua_State *L) {
	struct signalfd *S = luaL_checkudata(L, 1, LSL_CLASS);

	lua_settop(L, 2);

	lua_pushnumber(L, S->timeout);

	S->timeout = luaL_optnumber(L, 2, NAN);

	return 1;
} /* lsl_settimeout() */


static int lsl_type(lua_State *L) {
	if (luaL_testudata(L, 1, LSL_CLASS)) {
		lua_pushstring(L, "signal listener");
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* lsl_type() */


static int lsl_interpose(lua_State *L) {
	return cqs_interpose(L, LSL_CLASS);
} /* lsl_interpose() */


static int lsl_strflag(lua_State *L) {
	int top = lua_gettop(L), count = 0;

	for (int i = 1; i <= top; i++) {
		int flags = luaL_checkint(L, i);
		int flag;

		while ((flag = signal_flags(&flags))) {
			const char *txt;

			if (!(txt = signal_strflag(flag)))
				continue;
			luaL_checkstack(L, 1, "too many arguments");
			lua_pushstring(L, txt);
			count++;
		}
	}

	return count;
} /* lsl_strflag() */


static int lsl_nxtflag(lua_State *L) {
	int flags = (int)lua_tointeger(L, lua_upvalueindex(1));
	int flag;

	if ((flag = signal_flags(&flags))) {
		lua_pushinteger(L, flags);
		lua_replace(L, lua_upvalueindex(1));

		lua_pushinteger(L, flag);

		return 1;
	}

	return 0;
} /* lsl_nxtflag() */

static int lsl_flags(lua_State *L) {
	int i, flags = 0;

	for (i = 1; i <= lua_gettop(L); i++)
		flags |= luaL_checkint(L, i);

	lua_pushinteger(L, flags);
	lua_pushcclosure(L, &lsl_nxtflag, 1);

	return 1;
} /* lsl_flags() */


static const luaL_Reg lsl_methods[] = {
	{ "wait",       &lsl_wait },
	{ "pollfd",     &lsl_pollfd },
	{ "events",     &lsl_events },
	{ "timeout",    &lsl_timeout },
	{ "settimeout", &lsl_settimeout },
	{ NULL,         NULL },
}; /* lsl_methods[] */


static const luaL_Reg lsl_metatable[] = {
	{ "__gc", &lsl__gc },
	{ NULL,   NULL },
}; /* lsl_metatable[] */


/*
 * S I G N A L  D I S P O S I T I O N  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int ls_ignore(lua_State *L) {
	struct sigaction sa;
	int index;

	for (index = 1; index <= lua_gettop(L); index++) {
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;

		if (0 != sigaction(luaL_checkint(L, index), &sa, 0))
			return luaL_error(L, "signal.ignore: %s", cqs_strerror(errno));
	}

	lua_pushboolean(L, 1);

	return 1;
} /* ls_ignore() */


static int ls_default(lua_State *L) {
	struct sigaction sa;
	int index;

	for (index = 1; index <= lua_gettop(L); index++) {
		sa.sa_handler = SIG_DFL;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;

		if (0 != sigaction(luaL_checkint(L, index), &sa, 0))
			return luaL_error(L, "signal.default: %s", cqs_strerror(errno));
	}

	lua_pushboolean(L, 1);

	return 1;
} /* ls_default() */


static void ls_noop() {
	return;
} /* ls_noop() */

static int ls_discard(lua_State *L) {
	struct sigaction sa;
	int index;

	for (index = 1; index <= lua_gettop(L); index++) {
		sa.sa_handler = &ls_noop;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;

		if (0 != sigaction(luaL_checkint(L, index), &sa, 0))
			return luaL_error(L, "signal.discard: %s", cqs_strerror(errno));
	}

	lua_pushboolean(L, 1);

	return 1;
} /* ls_discard() */


static int ls_block(lua_State *L) {
	sigset_t set;
	int index, error;

	sigemptyset(&set);

	for (index = 1; index <= lua_gettop(L); index++) {
		sigaddset(&set, luaL_checkint(L, index));
	}

	if ((error = cqs_sigmask(SIG_BLOCK, &set, 0)))
		return luaL_error(L, "signal.block: %s", cqs_strerror(error));

	lua_pushboolean(L, 1);

	return 1;
} /* ls_block() */


static int ls_unblock(lua_State *L) {
	sigset_t set;
	int index, error;

	sigemptyset(&set);

	for (index = 1; index <= lua_gettop(L); index++) {
		sigaddset(&set, luaL_checkint(L, index));
	}

	if ((error = cqs_sigmask(SIG_UNBLOCK, &set, 0)))
		return luaL_error(L, "signal.unblock: %s", cqs_strerror(error));

	lua_pushboolean(L, 1);

	return 1;
} /* ls_unblock() */


static int ls_raise(lua_State *L) {
	int index;

	for (index = 1; index <= lua_gettop(L); index++) {
		raise(luaL_checkint(L, index));
	}

	lua_pushboolean(L, 1);

	return 1;
} /* ls_raise() */


static int ls_strsignal(lua_State *L) {
	lua_pushstring(L, strsignal(luaL_checkint(L, 1)));

	return 1;
} /* ls_strsignal() */


static const luaL_Reg ls_globals[] = {
	{ "listen",    &lsl_listen },
	{ "type",      &lsl_type },
	{ "interpose", &lsl_interpose },
	{ "strflag",   &lsl_strflag },
	{ "flags",     &lsl_flags },
	{ "interpose", &lsl_interpose },
	{ "ignore",    &ls_ignore },
	{ "default",   &ls_default },
	{ "discard",   &ls_discard },
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
		{ "SIGKILL", SIGKILL },
		{ "SIGPIPE", SIGPIPE },
		{ "SIGQUIT", SIGQUIT },
		{ "SIGTERM", SIGTERM },
		{ "SIGUSR1", SIGUSR1 },
		{ "SIGUSR2", SIGUSR2 },
	}, flag[] = {
		{ "SIGNALFD",      SIGNAL_SIGNALFD },
		{ "EVFILT_SIGNAL", SIGNAL_EVFILT_SIGNAL },
		{ "SIGTIMEDWAIT",  SIGNAL_SIGTIMEDWAIT },
		{ "KQUEUE",        SIGNAL_KQUEUE },
		{ "KQUEUE1",       SIGNAL_KQUEUE1 },
	};
	unsigned i;

	if (luaL_newmetatable(L, LSL_CLASS)) {
		luaL_setfuncs(L, lsl_metatable, 0);

		luaL_newlib(L, lsl_methods);
		lua_setfield(L, -2, "__index");
	}

	luaL_newlib(L, ls_globals);

	for (i = 0; i < sizeof siglist / sizeof *siglist; i++) {
		lua_pushinteger(L, siglist[i].value);
		lua_setfield(L, -2, siglist[i].name);

		lua_pushstring(L, siglist[i].name);
		lua_rawseti(L, -2, siglist[i].value);
	}

	for (i = 0; i < sizeof flag / sizeof *flag; i++) {
		lua_pushinteger(L, flag[i].value);
		lua_setfield(L, -2, flag[i].name);

		lua_pushstring(L, flag[i].name);
		lua_rawseti(L, -2, flag[i].value);
	}

	lua_pushinteger(L, signal_features());
	lua_setfield(L, -2, "FEATURES");

	return 1;
} /* luaopen__cqueues_signal() */

