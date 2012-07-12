/* ==========================================================================
 * errno.c.m4 - Lua Continuation Queues
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
#include <string.h>	/* strerror(3) strcmp(3) */

#include <errno.h>

#include <lua.h>
#include <lauxlib.h>

#include "lib/dns.h"
#include "lib/socket.h"


static const struct {
	const char *name;
	int value;
} errlist[] = {
changequote(<<<,>>>)dnl
esyscmd(<<<
../mk/errno.list | awk '{ print "#ifdef "$1"\n\t{ \""$1"\", "$1" },\n#endif" }'
>>>)dnl
};


static int le_strerror(lua_State *L) {
	int error = luaL_checkint(L, 1);

	if (error >= DNS_EBASE && error < DNS_ELAST)
		lua_pushstring(L, dns_strerror(error));
	else if (error >= SO_ERRNO0 && error < SO_EEND)
		lua_pushstring(L, so_strerror(error));
	else
		lua_pushstring(L, strerror(error));

	return 1;
} /* le_strerror() */


static const luaL_Reg le_globals[] = {
	{ "strerror", &le_strerror },
	{ NULL, NULL }
};


int luaopen__cqueues_errno(lua_State *L) {
	unsigned i;

	luaL_newlib(L, le_globals);

	for (i = 0; i < sizeof errlist / sizeof *errlist; i++) {
		lua_pushstring(L, errlist[i].name);
		lua_pushinteger(L, errlist[i].value);
		lua_settable(L, -3);

#if EAGAIN == EWOULDBLOCK
		if (!strcmp(errlist[i].name, "EWOULDBLOCK"))
			continue;
#endif

		lua_pushinteger(L, errlist[i].value);
		lua_pushstring(L, errlist[i].name);
		lua_settable(L, -3);
	}

	return 1;
} /* luaopen__cqueues_errno() */
