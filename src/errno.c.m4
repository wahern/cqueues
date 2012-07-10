changequote(<<<,>>>)dnl

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
syscmd(<<<
./errno.ls | awk '{ print "#ifdef "$1"\n\t{ \""$1"\", "$1" },\n#endif" }'
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


int luaopen_cqueues_errno(lua_State *L) {
	unsigned i;

	lua_newtable(L);
	luaL_setfuncs(L, le_globals, 0);

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
} /* luaopen_cqueues_errno() */

