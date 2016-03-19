/* ==========================================================================
 * notify.c - Lua Continuation Queues
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

#include "lib/notify.h"
#include "cqueues.h"


struct luanotify {
	struct notify *notify;
}; /* luanotify */


static int ln_step(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);
	int error;

	if ((error = notify_step(N->notify, 0))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* ln_step() */


static int ln_get(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);
	const char *name = 0;
	int changes;

	if (!(changes = notify_get(N->notify, &name)))
		return 0;

	lua_pushinteger(L, changes);
	lua_pushstring(L, name);

	return 2;
} /* ln_get() */


static int ln_add(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);
	const char *name = luaL_checkstring(L, 2);
	int flags = luaL_optinteger(L, 3, NOTIFY_ALL);
	int error;

	if ((error = notify_add(N->notify, name, flags))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* ln_add() */


static int ln_pollfd(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);

	lua_pushinteger(L, notify_pollfd(N->notify));

	return 1;
} /* ln_pollfd() */


static int ln_events(lua_State *L) {
	luaL_checkudata(L, 1, CQS_NOTIFY);

	lua_pushliteral(L, "r");

	return 1;
} /* ln_events() */


static int ln_timeout(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);
	int timeout;

	if ((timeout = notify_timeout(N->notify)) >= 0) {
		lua_pushnumber(L, (lua_Number)timeout / 1000);

		return 1;
	} else {
		return 0;
	}
} /* ln_timeout() */


static const luaL_Reg ln_methods[] = {
	{ "step",    &ln_step },
	{ "get",     &ln_get },
	{ "add",     &ln_add },
	{ "pollfd",  &ln_pollfd },
	{ "events",  &ln_events },
	{ "timeout", &ln_timeout },
	{ NULL,   NULL },
}; /* ln_methods[] */


static int ln__gc(lua_State *L) {
	struct luanotify *N = luaL_checkudata(L, 1, CQS_NOTIFY);

	notify_close(N->notify);
	N->notify = 0;

	return 0;
} /* ln__gc() */


static const luaL_Reg ln_metatable[] = {
	{ "__gc", &ln__gc },
	{ NULL,   NULL },
}; /* ln_metatable[] */


static int ln_opendir(lua_State *L) {
	const char *path = luaL_checkstring(L, 1);
	struct luanotify *N = 0;
	int error;

	N = lua_newuserdata(L, sizeof *N);
	N->notify = 0;
	luaL_setmetatable(L, CQS_NOTIFY);

	if (!(N->notify = notify_opendir(path, NOTIFY_ALL, &error)))
		goto error;

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* ln_opendir */


static int ln_type(lua_State *L) {
	if (luaL_testudata(L, 1, CQS_NOTIFY)) {
		lua_pushstring(L, "file notifier");
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* ln_type() */


static int ln_interpose(lua_State *L) {
	return cqs_interpose(L, CQS_NOTIFY);
} /* ln_interpose() */


static int ln_strflag(lua_State *L) {
	int flags = luaL_checkint(L, 1);
	int flag, count = 0;
	const char *name;

	while (ffs(flags)) {
		flag = 1 << (ffs(flags) - 1);
		flags &= ~flag;

		if ((name = notify_strflag(flag))) {
			lua_pushstring(L, name);
			count++;
		}
	}

	return count;
} /* ln_strflag() */


static int ln_nxtflag(lua_State *L) {
	int flags = (int)lua_tointeger(L, lua_upvalueindex(1));
	int flag;

	if (ffs(flags)) {
		flag = 1 << (ffs(flags) - 1);

		lua_pushinteger(L, flags & ~flag);
		lua_replace(L, lua_upvalueindex(1));

		lua_pushinteger(L, flag);

		return 1;
	}

	return 0;
} /* ln_nxtflag() */

static int ln_flags(lua_State *L) {
	int i, flags = 0;

	for (i = 1; i <= lua_gettop(L); i++)
		flags |= luaL_checkint(L, i);

	lua_pushinteger(L, flags);
	lua_pushcclosure(L, &ln_nxtflag, 1);

	return 1;
} /* ln_flags() */


static const luaL_Reg ln_globals[] = {
	{ "opendir",   &ln_opendir },
	{ "type",      &ln_type },
	{ "interpose", &ln_interpose },
	{ "strflag",   &ln_strflag },
	{ "flags",     &ln_flags },
	{ NULL,        NULL }
};


int luaopen__cqueues_notify(lua_State *L) {
	static const struct {
		const char *name;
		int value;
	} flag[] = {
		{ "CREATE", NOTIFY_CREATE },
		{ "DELETE", NOTIFY_DELETE },
		{ "ATTRIB", NOTIFY_ATTRIB },
		{ "MODIFY", NOTIFY_MODIFY },
		{ "REVOKE", NOTIFY_REVOKE },
		{ "ALL",    NOTIFY_ALL },

		{ "INOTIFY",    NOTIFY_INOTIFY },
		{ "FEN",        NOTIFY_FEN },
		{ "KQUEUE",     NOTIFY_KQUEUE },
		{ "KQUEUE1",    NOTIFY_KQUEUE1 },
		{ "OPENAT",     NOTIFY_OPENAT },
		{ "FDOPENDIR",  NOTIFY_FDOPENDIR},
		{ "O_CLOEXEC",  NOTIFY_O_CLOEXEC },
		{ "IN_CLOEXEC", NOTIFY_IN_CLOEXEC },
	};
	unsigned i;

	if (luaL_newmetatable(L, CQS_NOTIFY)) {
		luaL_setfuncs(L, ln_metatable, 0);

		luaL_newlib(L, ln_methods);
		lua_setfield(L, -2, "__index");
	}

	luaL_newlib(L, ln_globals);

	for (i = 0; i < countof(flag); i++) {
		lua_pushinteger(L, flag[i].value);
		lua_setfield(L, -2, flag[i].name);

		lua_pushinteger(L, flag[i].value);
		lua_pushstring(L, flag[i].name);
		lua_settable(L, -3);
	}

	lua_pushinteger(L, notify_features());
	lua_setfield(L, -2, "FEATURES");

	return 1;
} /* luaopen__cqueues_notify() */
