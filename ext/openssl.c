/* ==========================================================================
 * openssl.c - Lua OpenSSL
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
#ifndef L_OPENSSL_H
#define L_OPENSSH_H

#include <string.h>	/* memset(3) */

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define X509_NAME_CLASS "X.509 Name"
#define X509_CERT_CLASS "X.509 Cert"


static void *prepudata(lua_State *L, const char *tname, size_t size) {
	void *p = memset(lua_newuserdata(L, size), 0, size);
	luaL_setmetatable(L, tname);
	return p;
} /* prepudata() */


static void *prepsimple(lua_State *L, const char *tname) {
	void **p = prepudata(L, tname, sizeof (void *));
	return *p;
} /* presimple() */


static void *checksimple(lua_State *L, int index, const char *tname) {
	void **p = luaL_checkudata(L, index, tname);
	return *p;
} /* checksimple() */


static int throwssl(lua_State *L, const char *func) {
	/* FIXME */
	return luaL_error(L, "%s: SSL error (%lu)", func, ERR_get_error());
} /* throwssl() */


static int interpose(lua_State *L, const char *mt) {
	luaL_getmetatable(L, mt);
	lua_getfield(L, -1, "__index");

	lua_pushvalue(L, -4); /* push method name */
	lua_gettable(L, -2);  /* push old method */

	lua_pushvalue(L, -5); /* push method name */
	lua_pushvalue(L, -5); /* push new method */
	lua_settable(L, -4);  /* replace old method */

	return 1; /* return old method */
} /* interpose() */


static void addclass(lua_State *L, const char *name, const luaL_Reg *methods, const luaL_Reg *metamethods) {
	if (luaL_newmetatable(L, name)) {
		luaL_setfuncs(L, metamethods, 0);
		lua_newtable(L);
		luaL_setfuncs(L, methods, 0);
		lua_setfield(L, -2, "__index");
		lua_pop(L, 1);
	}
} /* addclass() */


/*
 * X509_NAME - openssl.x509.name
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static X509_NAME *xn_dup(lua_State *L, X509_NAME *name) {
	X509_NAME **ud = prepsimple(L, X509_NAME_CLASS);

	if (!(*ud = X509_NAME_dup(name)))
		throwssl(L, "x509.name.dup");

	return *ud;
} /* xn_dup() */


static int xn_new(lua_State *L) {
	X509_NAME **ud = prepsimple(L, X509_NAME_CLASS);

	if (!(*ud = X509_NAME_new()))
		return throwssl(L, "x509.name.new");

	return 1;
} /* xn_new() */


static int xn_interpose(lua_State *L) {
	return interpose(L, X509_NAME_CLASS);
} /* xn_interpose() */


static int xn_add(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	int nid;
	const char *txt;
	size_t len;

	if (NID_undef == (nid = OBJ_txt2nid(luaL_checkstring(L, 2))))
		return luaL_error(L, "x509.name:add: %s: invalid NID", luaL_checkstring(L, 2));

	txt = luaL_checklstring(L, 3, &len);

	if (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC, (unsigned char *)txt, len, -1, 0)))
		return throwssl(L, "x509.name:add");

	lua_pushboolean(L, 1);

	return 1;
} /* xn_add() */


static int xn__gc(lua_State *L) {
	X509_NAME **ud = luaL_checkudata(L, 1, X509_NAME_CLASS);

	X509_NAME_free(*ud);
	*ud = NULL;

	return 0;
} /* xn__gc() */


static const luaL_Reg xn_methods[] = {
	{ "add", &xn_add },
	{ NULL,  NULL },
};

static const luaL_Reg xn_metatable[] = {
	{ "__gc", &xn__gc },
	{ NULL,   NULL },
};


static const luaL_Reg xn_globals[] = {
	{ "new",       &xn_new },
	{ "interpose", &xn_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_name_open(lua_State *L) {
	addclass(L, X509_NAME_CLASS, xn_methods, xn_metatable);

	luaL_newlib(L, xn_globals);

	return 1;
} /* luaopen__openssl_x509_name_open() */



#endif /* L_OPENSSL_H */
