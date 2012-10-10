

static void luaL_setmetatable(lua_State *L, const char *tname) {
	luaL_getmetatable(L, tname);
	lua_setmetatable(L, -2);
} /* luaL_setmetatable() */


static int lua_absindex(lua_State *L, int idx) {
	return (idx > 0 || idx <= LUA_REGISTRYINDEX)? idx : lua_gettop(L) + idx + 1;
} /* lua_absindex() */


static void *luaL_testudata(lua_State *L, int arg, const char *tname) {
	void *p = lua_touserdata(L, arg);
	int eq;

	if (!p || !lua_getmetatable(L, arg))
		return 0;

	luaL_getmetatable(L, tname);
	eq = lua_rawequal(L, -2, -1);
	lua_pop(L, 2);

	return (eq)? p : 0;
} /* luaL_testudate() */


static void luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup) {
	int i, t = lua_absindex(L, -1 - nup);

	for (; l->name; l++) {
		for (i = 0; i < nup; i++)
			lua_pushvalue(L, -nup);
		lua_pushcclosure(L, l->func, nup);
		lua_setfield(L, t, l->name);
	}

	return lua_pop(L, nup);
} /* luaL_setfuncs() */


#define luaL_newlibtable(L, l) \
	lua_createtable(L, 0, (sizeof (l) / sizeof *(l)) - 1)

#define luaL_newlib(L, l) \
	(luaL_newlibtable((L), (l)), luaL_setfuncs((L), (l), 0))



