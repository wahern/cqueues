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
#include <math.h>	/* INFINITY fabs(3) floor(3) frexp(3) fmod(3) round(3) isfinite(3) */
#include <time.h>	/* struct tm time_t strptime(3) */

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define X509_NAME_CLASS "OpenSSL X.509 Name"
#define X509_CERT_CLASS "OpenSSL X.509 Cert"
#define BIGNUM_CLASS    "OpenSSL BN"


#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])

#define CLAMP(i, min, max) (((i) < (min))? (min) : ((i) > (max))? (max) : (i))


static void *prepudata(lua_State *L, const char *tname, size_t size) {
	void *p = memset(lua_newuserdata(L, size), 0, size);
	luaL_setmetatable(L, tname);
	return p;
} /* prepudata() */


static void *prepsimple(lua_State *L, const char *tname) {
	void **p = prepudata(L, tname, sizeof (void *));
	return p;
} /* presimple() */


static void *checksimple(lua_State *L, int index, const char *tname) {
	void **p = luaL_checkudata(L, index, tname);
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

		ctx = lua_newuserdata(L, sizeof *ctx);
		*ctx = NULL;

		lua_newtable(L);
		lua_pushcfunction(L, &ctx__gc);
		lua_setfield(L, -2, "__gc");
		lua_setmetatable(L, -2);

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
	BIGNUM *bn = checksimple(L, 1, X509_NAME_CLASS);
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

int luaopen__openssl_bignum_open(lua_State *L) {
	addclass(L, BIGNUM_CLASS, bn_methods, bn_metatable);

	luaL_newlib(L, bn_globals);

	return 1;
} /* luaopen__openssl_bignum_open() */


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

int luaopen__openssl_x509_name_open(lua_State *L) {
	addclass(L, X509_NAME_CLASS, xn_methods, xn_metatable);

	luaL_newlib(L, xn_globals);

	return 1;
} /* luaopen__openssl_x509_name_open() */


/*
 * X509_NAME - openssl.x509.name
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xc_new(lua_State *L) {
	X509 **ud = prepsimple(L, X509_CERT_CLASS);

	if (!(*ud = X509_new()))
		return throwssl(L, "x509.cert.new");

	X509_gmtime_adj(X509_get_notBefore(*ud), 0);
	X509_gmtime_adj(X509_get_notAfter(*ud), 0);

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


static int xc_getSerialNumber(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BIGNUM *serial = bn_push(L);
	ASN1_INTEGER *i;

	if ((i = X509_get_serialNumber(crt))) {
		if (!ASN1_INTEGER_to_BN(i, serial))
			return throwssl(L, "x509.cert:getSerialNumber");
	}

	return 1;
} /* xc_getSerialNumber() */


static int xc_setSerialNumber(lua_State *L) {
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

	return throwssl(L, "x509.cert:setSerialNumber");
} /* xc_setSerialNumber() */


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

		luaL_buffinitsize(L, &B, 2 * len);

		for (unsigned i = 0; i < len; i++) {
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

	return yday + (isleap(year) && mon > 1);
} /* yday() */


static int leaps(int year) {
	if (year >= 0)
		return (year / 400) + (year / 4) - (year / 100);
	else
		return -(leaps(-(year + 1)) + 1);
} /* leaps() */


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
	int gmtoff, year, i;
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
	
	ts = 86400.0 * 365.0 * (year - 1970);
	ts += 86400.0 * (leaps(year - 1) - leaps(1969));
	ts += 86400 * tm.tm_yday;
	ts += 3600 * tm.tm_hour;
	ts += 60 * tm.tm_min;
	ts += tm.tm_sec;
	ts += (year < 1970)? gmtoff : -gmtoff;

	return ts;
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


static int xc_issuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;
	
	lua_settop(L, 2);

	if ((name = X509_get_issuer_name(crt)))
		xn_dup(L, name);

	if (!lua_isnil(L, 2))
		X509_set_issuer_name(crt, checksimple(L, 2, X509_NAME_CLASS));

	return !!name;
} /* xc_issuer() */


static int xc__gc(lua_State *L) {
	X509 **ud = luaL_checkudata(L, 1, X509_CERT_CLASS);

	X509_free(*ud);
	*ud = NULL;

	return 0;
} /* xc__gc() */


static const luaL_Reg xc_methods[] = {
	{ "getVersion", &xc_getVersion },
	{ "setVersion", &xc_setVersion },
	{ NULL,      NULL },
};

static const luaL_Reg xc_metatable[] = {
	{ "__gc",       &xc__gc },
	{ NULL,         NULL },
};


static const luaL_Reg xc_globals[] = {
	{ "new",       &xc_new },
	{ "interpose", &xc_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_cert_open(lua_State *L) {
	addclass(L, X509_CERT_CLASS, xc_methods, xc_metatable);

	luaL_newlib(L, xc_globals);

	return 1;
} /* luaopen__openssl_x509_cert_open() */






#endif /* L_OPENSSL_H */
