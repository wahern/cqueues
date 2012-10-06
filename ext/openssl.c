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

#include <limits.h>	/* INT_MAX INT_MIN */
#include <string.h>	/* memset(3) */
#include <strings.h>	/* strcasecmp(3) */
#include <math.h>	/* INFINITY fabs(3) floor(3) frexp(3) fmod(3) round(3) isfinite(3) */
#include <time.h>	/* struct tm time_t strptime(3) */

#include <netinet/in.h>	/* struct in_addr struct in6_addr */
#include <arpa/inet.h>	/* AF_INET6 AF_INET inet_pton(3) */

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define X509_NAME_CLASS "OpenSSL X.509 Name"
#define X509_GENS_CLASS "OpenSSL X.509 AltName"
#define X509_CERT_CLASS "OpenSSL X.509 Cert"
#define BIGNUM_CLASS    "OpenSSL BN"


#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])

#define CLAMP(i, min, max) (((i) < (min))? (min) : ((i) > (max))? (max) : (i))

#define stricmp(a, b) strcasecmp((a), (b))
#define strieq(a, b) (!stricmp((a), (b)))


static void *prepudata(lua_State *L, size_t size, const char *tname, int (*gc)(lua_State *)) {
	void *p = memset(lua_newuserdata(L, size), 0, size);

	if (tname) {
		luaL_setmetatable(L, tname);
	} else {
		lua_newtable(L);
		lua_pushcfunction(L, gc);
		lua_setfield(L, -2, "__gc");
		lua_setmetatable(L, -2);
	}

	return p;
} /* prepudata() */


static void *prepsimple(lua_State *L, const char *tname, int (*gc)(lua_State *)) {
	void **p = prepudata(L, sizeof (void *), tname, gc);
	return p;
} /* prepsimple() */

#define prepsimple_(a, b, c, ...) prepsimple((a), (b), (c))
#define prepsimple(...) prepsimple_(__VA_ARGS__, 0)


static void *checksimple(lua_State *L, int index, const char *tname) {
	void **p;

	if (tname) {
		p = luaL_checkudata(L, index, tname);
	} else {
		luaL_checktype(L, index, LUA_TUSERDATA);
		p = lua_touserdata(L, index);
	}

	return *p;
} /* checksimple() */


static int throwssl(lua_State *L, const char *fun) {
	unsigned long code;
	const char *file;
	int line;
	char txt[256];

	code = ERR_get_error_line(&file, &line);
	ERR_clear_error();

	ERR_error_string_n(code, txt, sizeof txt);

	return luaL_error(L, "%s: %s:%d:%s", fun, file, line, txt);
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


static void initall(lua_State *L);


/*
 * BIGNUM - openssl.bignum
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static BIGNUM *bn_push(lua_State *L) {
	BIGNUM **ud = prepsimple(L, BIGNUM_CLASS);

	if (!(*ud = BN_new()))
		throwssl(L, "bignum.new");

	return *ud;
} /* bn_push() */


#define checkbig_(a, b, c, ...) checkbig((a), (b), (c))
#define checkbig(...) checkbig_(__VA_ARGS__, &(_Bool){ 0 })

static BIGNUM *(checkbig)(lua_State *, int, _Bool *);

static int bn_new(lua_State *L) {
	int i, n;

	if ((n = lua_gettop(L)) > 0) {
		for (i = 1; i <= n; i++)
			checkbig(L, i);

		return n;
	} else {
		bn_push(L);

		return 1;
	}
} /* bn_new() */


static int bn_interpose(lua_State *L) {
	return interpose(L, BIGNUM_CLASS);
} /* bn_interpose() */


/* return integral part */
static inline double intof(double f) {
	return (isfinite(f))? floor(fabs(f)) : 0.0;
} /* intof() */


/* convert integral to BN_ULONG. returns success or failure. */
static _Bool int2ul(BN_ULONG *ul, double f) {
	int exp;

	frexp(f, &exp);

	if (exp > (int)sizeof *ul * 8)
		return 0;

	*ul = (BN_ULONG)f;

	return 1;
} /* int2ul() */


/* convert integral BIGNUM. returns success or failure. */
static _Bool int2bn(BIGNUM **bn, double q) {
	unsigned char nib[32], bin[32], *p;
	size_t i, n;
	double r;

	p = nib;

	while (q >= 1.0 && p < endof(nib)) {
		r = fmod(q, 256.0);
		*p++ = r;
		q = round((q - r) / 256.0);
	}

	n = p - nib;

	for (i = 0; i < n; i++) {
		bin[i] = *--p;
	}

	if (!(*bn = BN_bin2bn(bin, n, *bn)))
		return 0;

	return 1;
} /* int2bn() */


/* convert double to BIGNUM. returns success or failure. */
static _Bool f2bn(BIGNUM **bn, double f) {
	double i = intof(f);
	BN_ULONG lu;

	if (int2ul(&lu, i)) {
		if (!*bn && !(*bn = BN_new()))
			return 0;

		if (!BN_set_word(*bn, lu))
			return 0;
	} else if (!int2bn(bn, i))
		return 0;

	BN_set_negative(*bn, signbit(f));

	return 1;
} /* f2bn() */


static BIGNUM *(checkbig)(lua_State *L, int index, _Bool *lvalue) {
	BIGNUM **bn;
	const char *dec;
	size_t len;

	index = lua_absindex(L, index);

	switch (lua_type(L, index)) {
	case LUA_TSTRING:
		*lvalue = 0;

		dec = lua_tolstring(L, index, &len);

		luaL_argcheck(L, len > 0 && *dec, index, "invalid big number string");

		bn = prepsimple(L, BIGNUM_CLASS);

		if (!BN_dec2bn(bn, dec))
			throwssl(L, "bignum");

		lua_replace(L, index);

		return *bn;
	case LUA_TNUMBER:
		*lvalue = 0;

		bn = prepsimple(L, BIGNUM_CLASS);

		if (!f2bn(bn, lua_tonumber(L, index)))
			throwssl(L, "bignum");

		lua_replace(L, index);

		return *bn;
	default:
		*lvalue = 1;

		return checksimple(L, index, BIGNUM_CLASS);
	} /* switch() */
} /* checkbig() */


static void bn_prepops(lua_State *L, BIGNUM **r, BIGNUM **a, BIGNUM **b, _Bool commute) {
	_Bool lvalue = 1;

	lua_settop(L, 2); /* a, b */

	*a = checkbig(L, 1, &lvalue);

	if (!lvalue && commute)
		lua_pushvalue(L, 1);

	*b = checkbig(L, 2, &lvalue);

	if (!lvalue && commute && lua_gettop(L) < 3)
		lua_pushvalue(L, 2);

	if (lua_gettop(L) < 3)
		bn_push(L);

	*r = *(BIGNUM **)lua_touserdata(L, 3);
} /* bn_prepops() */


static int ctx__gc(lua_State *L) {
	BN_CTX **ctx = lua_touserdata(L, 1);

	BN_CTX_free(*ctx);
	*ctx = NULL;

	return 0;
} /* ctx__gc() */

static BN_CTX *getctx(lua_State *L) {
	BN_CTX **ctx;

	lua_pushcfunction(L, &ctx__gc);
	lua_gettable(L, LUA_REGISTRYINDEX);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		ctx = prepsimple(L, NULL, &ctx__gc);

		if (!(*ctx = BN_CTX_new()))
			throwssl(L, "bignum");

		lua_pushcfunction(L, &ctx__gc);
		lua_pushvalue(L, -2);
		lua_settable(L, LUA_REGISTRYINDEX);
		
	}

	ctx = lua_touserdata(L, -1);
	lua_pop(L, 1);

	return *ctx;
} /* getctx() */


static int bn__add(lua_State *L) {
	BIGNUM *r, *a, *b;

	bn_prepops(L, &r, &a, &b, 1);

	if (!BN_add(r, a, b))
		return throwssl(L, "bignum:__add");

	return 1;
} /* bn__add() */


static int bn__sub(lua_State *L) {
	BIGNUM *r, *a, *b;

	bn_prepops(L, &r, &a, &b, 0);

	if (!BN_sub(r, a, b))
		return throwssl(L, "bignum:__sub");

	return 1;
} /* bn__sub() */


static int bn__mul(lua_State *L) {
	BIGNUM *r, *a, *b;

	bn_prepops(L, &r, &a, &b, 1);

	if (!BN_mul(r, a, b, getctx(L)))
		return throwssl(L, "bignum:__mul");

	return 1;
} /* bn__mul() */


static int bn__div(lua_State *L) {
	BIGNUM *r, *a, *b;
	BN_CTX *ctx;

	bn_prepops(L, &r, &a, &b, 0);

	if (!BN_div(r, NULL, a, b, getctx(L)))
		return throwssl(L, "bignum:__div");

	return 1;
} /* bn__div() */


static int bn__mod(lua_State *L) {
	BIGNUM *r, *a, *b;
	BN_CTX *ctx;

	bn_prepops(L, &r, &a, &b, 0);

	if (!BN_mod(r, a, b, getctx(L)))
		return throwssl(L, "bignum:__mod");

	return 1;
} /* bn__mod() */


static int bn__pow(lua_State *L) {
	BIGNUM *r, *a, *b;
	BN_CTX *ctx;

	bn_prepops(L, &r, &a, &b, 0);

	if (!BN_exp(r, a, b, getctx(L)))
		return throwssl(L, "bignum:__pow");

	return 1;
} /* bn__pow() */


static int bn__unm(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);

	BN_set_negative(a, !BN_is_negative(a));

	return 1;
} /* bn__unm() */


static int bn__eq(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);

	lua_pushboolean(L, 0 == BN_cmp(a, b));

	return 1;
} /* bn__eq() */


static int bn__lt(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);
	int cmp = BN_cmp(a, b);

	lua_pushboolean(L, cmp == -1);

	return 1;
} /* bn__lt() */


static int bn__le(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);
	int cmp = BN_cmp(a, b);

	lua_pushboolean(L, cmp <= 0);

	return 1;
} /* bn__le() */


static int bn__gc(lua_State *L) {
	BIGNUM **ud = luaL_checkudata(L, 1, BIGNUM_CLASS);

	BN_free(*ud);
	*ud = NULL;

	return 0;
} /* bn__gc() */


static int bn__tostring(lua_State *L) {
	BIGNUM *bn = checksimple(L, 1, BIGNUM_CLASS);
	char *txt;

	if (!(txt = BN_bn2dec(bn)))
		throwssl(L, "bignum:__tostring");

	lua_pushstring(L, txt);

	return 1;
} /* bn__tostring() */


static const luaL_Reg bn_methods[] = {
	{ NULL,  NULL },
};

static const luaL_Reg bn_metatable[] = {
	{ "__add",      &bn__add },
	{ "__sub",      &bn__sub },
	{ "__mul",      &bn__mul },
	{ "__div",      &bn__div },
	{ "__mod",      &bn__mod },
	{ "__pow",      &bn__pow },
	{ "__unm",      &bn__unm },
	{ "__eq",       &bn__eq },
	{ "__lt",       &bn__lt },
	{ "__le",       &bn__le },
	{ "__gc",       &bn__gc },
	{ "__tostring", &bn__tostring },
	{ NULL,         NULL },
};


static const luaL_Reg bn_globals[] = {
	{ "new",       &bn_new },
	{ "interpose", &bn_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_bignum(lua_State *L) {
	initall(L);

	luaL_newlib(L, bn_globals);

	return 1;
} /* luaopen__openssl_bignum() */


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
	const char *nid = luaL_checkstring(L, 2);
	size_t len;
	const char *txt = luaL_checklstring(L, 3, &len);
	ASN1_OBJECT *obj;
	int ok;

	if (!(obj = OBJ_txt2obj(nid, 0)))
		return luaL_error(L, "x509.name:add: %s: invalid NID", nid);

	ok = !!X509_NAME_add_entry_by_OBJ(name, obj, MBSTRING_ASC, (unsigned char *)txt, len, -1, 0);

	ASN1_OBJECT_free(obj);

	if (!ok)
		return throwssl(L, "x509.name:add");

	lua_pushboolean(L, 1);

	return 1;
} /* xn_add() */


static int xn_all(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	int count = X509_NAME_entry_count(name);
	X509_NAME_ENTRY *entry;
	ASN1_OBJECT *obj;
	const char *id;
	char txt[256];
	int i, nid, len;

	lua_newtable(L);

	for (i = 0; i < count; i++) {
		if (!(entry = X509_NAME_get_entry(name, i)))
			continue;

		lua_newtable(L);

		obj = X509_NAME_ENTRY_get_object(entry);
		nid = OBJ_obj2nid(obj);

		if (0 > (len = OBJ_obj2txt(txt, sizeof txt, obj, 1)))
			return throwssl(L, "x509.name:all");

		lua_pushlstring(L, txt, len);

		if (nid != NID_undef && ((id = OBJ_nid2ln(nid)) || (id = OBJ_nid2sn(nid))))
			lua_pushstring(L, id);
		else
			lua_pushvalue(L, -1);

		if (nid != NID_undef && (id = OBJ_nid2sn(nid)))
			lua_pushstring(L, id);
		else
			lua_pushvalue(L, -1);

		lua_setfield(L, -4, "sn");
		lua_setfield(L, -3, "ln");
		lua_setfield(L, -2, "id");

		len = ASN1_STRING_length(X509_NAME_ENTRY_get_data(entry));
		lua_pushlstring(L, (char *)ASN1_STRING_data(X509_NAME_ENTRY_get_data(entry)), len);

		lua_setfield(L, -2, "blob");

		lua_rawseti(L, -2, i + 1);
	}

	return 1;
} /* xn_all() */


static int xn__gc(lua_State *L) {
	X509_NAME **ud = luaL_checkudata(L, 1, X509_NAME_CLASS);

	X509_NAME_free(*ud);
	*ud = NULL;

	return 0;
} /* xn__gc() */


static int xn__tostring(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	char txt[1024] = { 0 };

	/* FIXME: oneline is deprecated */
	X509_NAME_oneline(name, txt, sizeof txt);

	lua_pushstring(L, txt);

	return 1;
} /* xn__tostring() */


static const luaL_Reg xn_methods[] = {
	{ "add", &xn_add },
	{ "all", &xn_all },
	{ NULL,  NULL },
};

static const luaL_Reg xn_metatable[] = {
	{ "__gc",       &xn__gc },
	{ "__tostring", &xn__tostring },
	{ NULL,         NULL },
};


static const luaL_Reg xn_globals[] = {
	{ "new",       &xn_new },
	{ "interpose", &xn_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_name(lua_State *L) {
	initall(L);

	luaL_newlib(L, xn_globals);

	return 1;
} /* luaopen__openssl_x509_name() */


/*
 * GENERAL_NAMES - openssl.x509.altname
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static GENERAL_NAMES *gn_dup(lua_State *L, GENERAL_NAMES *gens) {
	GENERAL_NAMES **ud = prepsimple(L, X509_GENS_CLASS);

	if (!(*ud = sk_GENERAL_NAMES_dup(gens)))
		throwssl(L, "x509.altname.dup");

	return *ud;
} /* gn_dup() */


static int gn_new(lua_State *L) {
	GENERAL_NAMES **ud = prepsimple(L, X509_GENS_CLASS);

	if (!(*ud = sk_GENERAL_NAME_new_null()))
		return throwssl(L, "x509.altname.new");

	return 1;
} /* gn_new() */


static int gn_interpose(lua_State *L) {
	return interpose(L, X509_GENS_CLASS);
} /* gn_interpose() */


static int gn_setCritical(lua_State *L) {
	GENERAL_NAMES *gens = checksimple(L, 1, X509_GENS_CLASS);

	return 0;
} /* gn_setCritical() */


static int gn_checktype(lua_State *L, int index) {
	static const struct { int type; const char *name; } table[] = {
		{ GEN_EMAIL, "RFC822Name" },
		{ GEN_EMAIL, "RFC822" },
		{ GEN_EMAIL, "email" },
		{ GEN_URI,   "UniformResourceIdentifier" },
		{ GEN_URI,   "URI" },
		{ GEN_DNS,   "DNSName" },
		{ GEN_DNS,   "DNS" },
		{ GEN_IPADD, "IPAddress" },
		{ GEN_IPADD, "IP" },
	};
	const char *type = luaL_checkstring(L, index);
	unsigned i;

	for (i = 0; i < countof(table); i++) {
		if (strieq(table[i].name, type))
			return table[i].type;
	}

	return luaL_error(L, "%s: invalid type", type), 0;
} /* gn_checktype() */


static int gn_add(lua_State *L) {
	GENERAL_NAMES *gens = checksimple(L, 1, X509_GENS_CLASS);
	int type = gn_checktype(L, 2);
	size_t len;
	const char *txt = luaL_checklstring(L, 3, &len);
	GENERAL_NAME *gen = NULL;
	union { struct in6_addr in6; struct in_addr in; } ip;

	if (type == GEN_IPADD) {
		if (strchr(txt, ':')) {
			if (1 != inet_pton(AF_INET6, txt, &ip.in6))
				return luaL_error(L, "%s: invalid address", txt);

			txt = (char *)ip.in6.s6_addr;
			len = 16;
		} else {
			if (1 != inet_pton(AF_INET, txt, &ip.in))
				return luaL_error(L, "%s: invalid address", txt);

			txt = (char *)&ip.in.s_addr;
			len = 4;
		}
	}

	if (!(gen = GENERAL_NAME_new()))
		goto error;

	gen->type = type;

	if (!(gen->d.ia5 = M_ASN1_IA5STRING_new()))
		goto error;

	if (!ASN1_STRING_set(gen->d.ia5, (unsigned char *)txt, len))
		goto error;

	sk_GENERAL_NAME_push(gens, gen);

	lua_pushboolean(L, 1);

	return 1;
error:
	GENERAL_NAME_free(gen);

	return throwssl(L, "x509.altname:add");
} /* gn_add() */


static int gn__next(lua_State *L) {
	GENERAL_NAMES *gens = checksimple(L, lua_upvalueindex(1), X509_GENS_CLASS);
	int i = lua_tointeger(L, lua_upvalueindex(2));
	int n = sk_GENERAL_NAME_num(gens);

	lua_settop(L, 0);

	while (i < n) {
		GENERAL_NAME *name;
		const char *tag, *txt;
		size_t len;
		union { struct in_addr in; struct in6_addr in6; } ip;
		char buf[INET6_ADDRSTRLEN + 1];
		int af;

		if (!(name = sk_GENERAL_NAME_value(gens, i++)))
			continue;

		switch (name->type) {
		case GEN_EMAIL:
			tag = "RFC822";
			txt = (char *)M_ASN1_STRING_data(name->d.rfc822Name);
			len = M_ASN1_STRING_length(name->d.rfc822Name);

			break;
		case GEN_URI:
			tag = "URI";
			txt = (char *)M_ASN1_STRING_data(name->d.uniformResourceIdentifier);
			len = M_ASN1_STRING_length(name->d.uniformResourceIdentifier);

			break;
		case GEN_DNS:
			tag = "DNS";
			txt = (char *)M_ASN1_STRING_data(name->d.dNSName);
			len = M_ASN1_STRING_length(name->d.dNSName);

			break;
		case GEN_IPADD:
			tag = "IP";
			txt = (char *)M_ASN1_STRING_data(name->d.iPAddress);
			len = M_ASN1_STRING_length(name->d.iPAddress);

			switch (len) {
			case 16:
				memcpy(ip.in6.s6_addr, txt, 16);
				af = AF_INET6;

				break;
			case 4:
				memcpy(&ip.in.s_addr, txt, 4);
				af = AF_INET;

				break;
			default:
				continue;
			}

			if (!(txt = inet_ntop(af, &ip, buf, sizeof buf)))
				continue;

			len = strlen(txt);

			break;
		default:
			continue;
		}

		lua_pushstring(L, tag);
		lua_pushlstring(L, txt, len);

		break;
	}

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* gn__next() */

static int gn__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, &gn__next, 2);

	return 1;
} /* gn__pairs() */


static int gn__gc(lua_State *L) {
	GENERAL_NAMES **ud = luaL_checkudata(L, 1, X509_GENS_CLASS);

	sk_GENERAL_NAME_pop_free(*ud, GENERAL_NAME_free);
	*ud = NULL;

	return 0;
} /* gn__gc() */


static const luaL_Reg gn_methods[] = {
	{ "add", &gn_add },
	{ NULL,  NULL },
};

static const luaL_Reg gn_metatable[] = {
	{ "__pairs", &gn__pairs },
	{ "__gc",    &gn__gc },
	{ NULL,      NULL },
};


static const luaL_Reg gn_globals[] = {
	{ "new",       &gn_new },
	{ "interpose", &gn_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_altname(lua_State *L) {
	initall(L);

	luaL_newlib(L, gn_globals);

	return 1;
} /* luaopen__openssl_x509_altname() */


/*
 * X509 - openssl.x509.cert
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xc_new(lua_State *L) {
	const char *pem;
	size_t len;
	X509 **ud;

	lua_settop(L, 1);

	ud = prepsimple(L, X509_CERT_CLASS);

	if ((pem = luaL_optlstring(L, 1, NULL, &len))) {
		BIO *tmp;
		int ok;

		if (!(tmp = BIO_new_mem_buf((char *)pem, len)))
			return throwssl(L, "x509.cert.new");

		ok = !!PEM_read_bio_X509(tmp, ud, 0, ""); /* no password */

		BIO_free(tmp);

		if (!ok)
			return throwssl(L, "x509.cert.new");
	} else {
		if (!(*ud = X509_new()))
			return throwssl(L, "x509.cert.new");

		X509_gmtime_adj(X509_get_notBefore(*ud), 0);
		X509_gmtime_adj(X509_get_notAfter(*ud), 0);
	}

	return 1;
} /* xc_new() */


static int xc_interpose(lua_State *L) {
	return interpose(L, X509_CERT_CLASS);
} /* xc_interpose() */


static int xc_getVersion(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushinteger(L, X509_get_version(crt) + 1);

	return 1;
} /* xc_getVersion() */


static int xc_setVersion(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int version = luaL_checkint(L, 2);

	if (!X509_set_version(crt, version - 1))
		return luaL_error(L, "x509.cert:setVersion: %d: invalid version", version);

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setVersion() */


static int xc_getSerial(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BIGNUM *serial = bn_push(L);
	ASN1_INTEGER *i;

	if ((i = X509_get_serialNumber(crt))) {
		if (!ASN1_INTEGER_to_BN(i, serial))
			return throwssl(L, "x509.cert:getSerial");
	}

	return 1;
} /* xc_getSerial() */


static int xc_setSerial(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	ASN1_INTEGER *serial;

	if (!(serial = BN_to_ASN1_INTEGER(checkbig(L, 2), NULL)))
		goto error;

	if (!X509_set_serialNumber(crt, serial))
		goto error;

	ASN1_INTEGER_free(serial);

	lua_pushboolean(L, 1);

	return 1;
error:
	ASN1_INTEGER_free(serial);

	return throwssl(L, "x509.cert:setSerial");
} /* xc_setSerial() */


static int xc_digest(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	const char *type = luaL_optstring(L, 2, "sha1");
	int format = luaL_checkoption(L, 3, "*s", (const char *[]){ "*s", "*x", "*n", NULL });
	const EVP_MD *ctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len;

	lua_settop(L, 3); /* self, type, hex */

	if (!(ctx = EVP_get_digestbyname(type)))
		return luaL_error(L, "x509.cert:digest: %s: invalid digest type", type);

	X509_digest(crt, ctx, md, &len);

	switch (format) {
	case 2: {
		BIGNUM *bn = bn_push(L);

		if (!BN_bin2bn(md, len, bn))
			return throwssl(L, "x509.cert:digest");

		break;
	}
	case 1: {
		static const unsigned char x[16] = "0123456789abcdef";
		luaL_Buffer B;
		unsigned i;

		luaL_buffinitsize(L, &B, 2 * len);

		for (i = 0; i < len; i++) {
			luaL_addchar(&B, x[0x0f & (md[i] >> 4)]);
			luaL_addchar(&B, x[0x0f & (md[i] >> 0)]);
		}

		luaL_pushresult(&B);

		break;
	}
	default:
		lua_pushlstring(L, (const char *)md, len);

		break;
	} /* switch() */

	return 1;
} /* xc_digest() */


static _Bool isleap(int year) {
	if (year >= 0)
		return !(year % 4) && ((year % 100) || !(year % 400));
	else
		return isleap(-(year + 1));
} /* isleap() */


static int yday(int year, int mon, int mday) {
	static const int past[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
	int yday = past[CLAMP(mon, 0, 11)] + CLAMP(mday, 1, 31) - 1;

	return yday + (mon > 1 && isleap(year));
} /* yday() */


static int tm_yday(const struct tm *tm) {
	return (tm->tm_yday)? tm->tm_yday : yday(1900 + tm->tm_year, tm->tm_mon, tm->tm_mday);
} /* tm_yday() */


static int leaps(int year) {
	if (year >= 0)
		return (year / 400) + (year / 4) - (year / 100);
	else
		return -(leaps(-(year + 1)) + 1);
} /* leaps() */


static double tm2unix(const struct tm *tm, int gmtoff) {
	int year = tm->tm_year + 1900;
	double ts;

	ts = 86400.0 * 365.0 * (year - 1970);
	ts += 86400.0 * (leaps(year - 1) - leaps(1969));
	ts += 86400 * tm_yday(tm);
	ts += 3600 * tm->tm_hour;
	ts += 60 * tm->tm_min;
	ts += CLAMP(tm->tm_sec, 0, 59);
	ts += (year < 1970)? gmtoff : -gmtoff;

	return ts;
} /* tm2unix() */


static _Bool scan(int *i, char **cp, int n, int signok) {
	int sign = 1;

	*i = 0;

	if (signok) {
		if (**cp == '-') {
			sign = -1;
			++*cp;
		} else if (**cp == '+') {
			++*cp;
		}
	}

	while (n-- > 0) {
		if (**cp < '0' || **cp > '9')
			return 0;

		*i *= 10;
		*i += *(*cp)++ - '0';
	}

	*i *= sign;

	return 1;
} /* scan() */


static double timeutc(ASN1_TIME *time) {
	char buf[32] = "", *cp;
	struct tm tm;
	int gmtoff = 0, year, i;
	double ts;

	if (!ASN1_TIME_check(time))
		return 0;

	cp = strncpy(buf, (const char *)ASN1_STRING_data((ASN1_STRING *)time), sizeof buf - 1);

	if (ASN1_STRING_type(time) == V_ASN1_GENERALIZEDTIME) {
		if (!scan(&year, &cp, 4, 1))
			goto badfmt;
	} else {
		if (!scan(&year, &cp, 2, 0))
			goto badfmt;
		year += (year < 50)? 2000 : 1999;
	}

	tm.tm_year = year - 1900;

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_mon = CLAMP(i, 1, 12) - 1;

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_mday = CLAMP(i, 1, 31);

	tm.tm_yday = yday(year, tm.tm_mon, tm.tm_mday);

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_hour = CLAMP(i, 0, 23);

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_min = CLAMP(i, 0, 59);

	if (*cp >= '0' && *cp <= '9') {
		if (!scan(&i, &cp, 2, 0))
			goto badfmt;

		tm.tm_sec = CLAMP(i, 0, 59);
	}

	if (*cp == '+' || *cp == '-') {
		int sign = (*cp++ == '-')? -1 : 1;
		int hh, mm;

		if (!scan(&hh, &cp, 2, 0) || !scan(&mm, &cp, 2, 0))
			goto badfmt;

		gmtoff = (CLAMP(hh, 0, 23) * 3600)
		       + (CLAMP(mm, 0, 59) * 60);

		gmtoff *= sign;
	}
	
	return tm2unix(&tm, gmtoff);
badfmt:
	return INFINITY;
} /* timeutc() */


static int xc_getLifetime(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	double begin = INFINITY, end = INFINITY;
	ASN1_TIME *time;

	if ((time = X509_get_notBefore(crt)))
		begin = timeutc(time);

	if ((time = X509_get_notAfter(crt)))
		end = timeutc(time);

	if (isfinite(begin))
		lua_pushnumber(L, begin);
	else
		lua_pushnil(L);

	if (isfinite(end))
		lua_pushnumber(L, end);
	else
		lua_pushnil(L);

	if (isfinite(begin) && isfinite(end) && begin <= end)
		lua_pushnumber(L, fabs(end - begin));
	else
		lua_pushnumber(L, 0.0);

	return 3;
} /* xc_getLifetime() */


static int xc_setLifetime(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	ASN1_TIME *time;
	double ut;
	const char *dt;

	lua_settop(L, 3);

	if (lua_isnumber(L, 2)) {
		ut = lua_tonumber(L, 2);

		if (!ASN1_TIME_set(X509_get_notBefore(crt), ut))
			return throwssl(L, "x509.cert:setLifetime");
#if 0
	} else if ((dt = luaL_optstring(L, 2, 0))) {
		if (!ASN1_TIME_set_string(X509_get_notBefore(crt), dt))
			return throwssl(L, "x509.cert:setLifetime");
#endif
	}

	if (lua_isnumber(L, 3)) {
		ut = lua_tonumber(L, 3);

		if (!ASN1_TIME_set(X509_get_notAfter(crt), ut))
			return throwssl(L, "x509.cert:setLifetime");
#if 0
	} else if ((dt = luaL_optstring(L, 3, 0))) {
		if (!ASN1_TIME_set_string(X509_get_notAfter(crt), dt))
			return throwssl(L, "x509.cert:setLifetime");
#endif
	}

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setLifetime() */


static int xc_getIssuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;
	
	if ((name = X509_get_issuer_name(crt)))
		xn_dup(L, name);

	return !!name;
} /* xc_getIssuer() */


static int xc_setIssuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_issuer_name(crt, name))
		return throwssl(L, "x509.cert:setIssuer");

	return !!name;
} /* xc_setIssuer() */


static int xc_getSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;
	
	if ((name = X509_get_subject_name(crt)))
		xn_dup(L, name);

	return !!name;
} /* xc_getSubject() */


static int xc_setSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_subject_name(crt, name))
		return throwssl(L, "x509.cert:setSubject");

	return !!name;
} /* xc_setSubject() */


static void xc_setCritical(X509 *crt, int nid, _Bool yes) {
	X509_EXTENSION *ext;
	int loc;

	if ((loc = X509_get_ext_by_NID(crt, nid, -1)) >= 0
	&&  (ext = X509_get_ext(crt, loc)))
		X509_EXTENSION_set_critical(ext, yes);
} /* xc_setCritical() */


static _Bool xc_getCritical(X509 *crt, int nid) {
	X509_EXTENSION *ext;
	int loc;

	if ((loc = X509_get_ext_by_NID(crt, nid, -1)) >= 0
	&&  (ext = X509_get_ext(crt, loc)))
		return X509_EXTENSION_get_critical(ext);
	else
		return 0;
} /* xc_getCritical() */


static int xc_getIssuerAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens;

	if (!(gens = X509_get_ext_d2i(crt, NID_issuer_alt_name, 0, 0)))
		return 0;

	gn_dup(L, gens);

	return 1;
} /* xc_getIssuerAlt() */


static int xc_setIssuerAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens = checksimple(L, 2, X509_GENS_CLASS);

	if (!X509_add1_ext_i2d(crt, NID_issuer_alt_name, gens, 0, X509V3_ADD_REPLACE))
		return throwssl(L, "x509.altname:setIssuerAlt");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuerAlt() */


static int xc_getSubjectAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens;

	if (!(gens = X509_get_ext_d2i(crt, NID_subject_alt_name, 0, 0)))
		return 0;

	gn_dup(L, gens);

	return 1;
} /* xc_getSubjectAlt() */


static int xc_setSubjectAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens = checksimple(L, 2, X509_GENS_CLASS);

	if (!X509_add1_ext_i2d(crt, NID_subject_alt_name, gens, 0, X509V3_ADD_REPLACE))
		return throwssl(L, "x509.altname:setSubjectAlt");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setSubjectAlt() */


static int xc_getIssuerAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_issuer_alt_name));

	return 1;
} /* xc_getIssuerAltCritical() */


static int xc_setIssuerAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_issuer_alt_name, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuerAltCritical() */


static int xc_getSubjectAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_subject_alt_name));

	return 1;
} /* xc_getSubjectAltCritical() */


static int xc_setSubjectAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_subject_alt_name, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setSubjectAltCritical() */


static int xc__tostring(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int fmt = luaL_checkoption(L, 2, "pem", (const char *[]){ "pem", 0 });
	BIO *tmp;
	char *pem;
	long len;

	if (!(tmp = BIO_new(BIO_s_mem())))
		return throwssl(L, "x509.cert:__tostring");

	if (!PEM_write_bio_X509(tmp, crt)) {
		BIO_free(tmp);

		return throwssl(L, "x509.cert:__tostring");
	}

	len = BIO_get_mem_data(tmp, &pem);

	/* FIXME: leaks on panic */

	lua_pushlstring(L, pem, len);

	BIO_free(tmp);

	return 1;
} /* xc__tostring() */


static int xc__gc(lua_State *L) {
	X509 **ud = luaL_checkudata(L, 1, X509_CERT_CLASS);

	X509_free(*ud);
	*ud = NULL;

	return 0;
} /* xc__gc() */


static const luaL_Reg xc_methods[] = {
	{ "getVersion",    &xc_getVersion },
	{ "setVersion",    &xc_setVersion },
	{ "getSerial",     &xc_getSerial },
	{ "setSerial",     &xc_setSerial },
	{ "digest",        &xc_digest },
	{ "getLifetime",   &xc_getLifetime },
	{ "setLifetime",   &xc_setLifetime },
	{ "getIssuer",     &xc_getIssuer },
	{ "setIssuer",     &xc_setIssuer },
	{ "getSubject",    &xc_getSubject },
	{ "setSubject",    &xc_setSubject },
	{ "getIssuerAlt",  &xc_getIssuerAlt },
	{ "setIssuerAlt",  &xc_setIssuerAlt },
	{ "getSubjectAlt", &xc_getSubjectAlt },
	{ "setSubjectAlt", &xc_setSubjectAlt },
	{ "getIssuerAltCritical",  &xc_getIssuerAltCritical },
	{ "setIssuerAltCritical",  &xc_setIssuerAltCritical },
	{ "getSubjectAltCritical", &xc_getSubjectAltCritical },
	{ "setSubjectAltCritical", &xc_setSubjectAltCritical },
	{ NULL,            NULL },
};

static const luaL_Reg xc_metatable[] = {
	{ "__tostring", &xc__tostring },
	{ "__gc",       &xc__gc },
	{ NULL,         NULL },
};


static const luaL_Reg xc_globals[] = {
	{ "new",       &xc_new },
	{ "interpose", &xc_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_cert(lua_State *L) {
	initall(L);

	luaL_newlib(L, xc_globals);

	return 1;
} /* luaopen__openssl_x509_cert() */


static void initall(lua_State *L) {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	addclass(L, BIGNUM_CLASS, bn_methods, bn_metatable);
	addclass(L, X509_NAME_CLASS, xn_methods, xn_metatable);
	addclass(L, X509_GENS_CLASS, gn_methods, gn_metatable);
	addclass(L, X509_CERT_CLASS, xc_methods, xc_metatable);
} /* initall() */


#endif /* L_OPENSSL_H */
