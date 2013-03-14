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

#include <sys/types.h>
#include <sys/stat.h>	/* struct stat stat(2) */
#include <sys/socket.h>	/* AF_INET AF_INET6 */

#include <netinet/in.h>	/* struct in_addr struct in6_addr */
#include <arpa/inet.h>	/* inet_pton(3) */

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM < 502
#include "compat52.h"
#endif

#define BIGNUM_CLASS     "OpenSSL Bignum"
#define PUBKEY_CLASS     "OpenSSL Pubkey"
#define X509_NAME_CLASS  "OpenSSL X.509 Name"
#define X509_GENS_CLASS  "OpenSSL X.509 AltName"
#define X509_CERT_CLASS  "OpenSSL X.509"
#define X509_CHAIN_CLASS "OpenSSL X.509 Chain"
#define X509_CSR_CLASS   "OpenSSL X.509 Request"
#define X509_CHAIN_CLASS "OpenSSL X.509 Chain"
#define X509_STORE_CLASS "OpenSSL X.509 Store"
#define X509_STCTX_CLASS "OpenSSL X.509 Store Context"
#define SSL_CTX_CLASS    "OpenSSL SSL Context"
#define SSL_CLASS        "OpenSSL SSL"
#define DIGEST_CLASS     "OpenSSL Digest"
#define HMAC_CLASS       "OpenSSL HMAC"
#define CIPHER_CLASS     "OpenSSL Cipher"


#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])

#define CLAMP(i, min, max) (((i) < (min))? (min) : ((i) > (max))? (max) : (i))

#undef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))

#define stricmp(a, b) strcasecmp((a), (b))
#define strieq(a, b) (!stricmp((a), (b)))

#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")


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


static void *testsimple(lua_State *L, int index, const char *tname) {
	void **p;

	if (tname) {
		p = luaL_testudata(L, index, tname);
	} else {
		luaL_checktype(L, index, LUA_TUSERDATA);
		p = lua_touserdata(L, index);
	}

	return (p)? *p : (void *)0;
} /* testsimple() */


static const char *pusherror(lua_State *L, const char *fun) {
	unsigned long code;
	const char *path, *file;
	int line;
	char txt[256];

	code = ERR_get_error_line(&path, &line);

	if ((file = strrchr(path, '/')))
		++file;
	else
		file = path;

	ERR_clear_error();

	ERR_error_string_n(code, txt, sizeof txt);

	if (fun)
		return lua_pushfstring(L, "%s: %s:%d:%s", fun, file, line, txt);
	else
		return lua_pushfstring(L, "%s:%d:%s", file, line, txt);
} /* pusherror() */


static int throwssl(lua_State *L, const char *fun) {
	pusherror(L, fun);

	return lua_error(L);
} /* throwssl() */


static int interpose(lua_State *L, const char *mt) {
	luaL_getmetatable(L, mt);

	if (!strncmp("__", luaL_checkstring(L, 1), 2))
		lua_pushvalue(L, -1);
	else
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


static int checkoption(struct lua_State *L, int index, const char *def, const char *opts[]) {
	const char *opt = (def)? luaL_optstring(L, index, def) : luaL_checkstring(L, index);
	int i; 

	for (i = 0; opts[i]; i++) {
		if (strieq(opts[i], opt))
			return i;
	}

	return luaL_argerror(L, index, lua_pushfstring(L, "invalid option %s", opt));
} /* checkoption() */


static _Bool getfield(lua_State *L, int index, const char *k) {
	lua_getfield(L, index, k);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		return 0;
	} else {
		return 1;
	}
} /* getfield() */


static _Bool loadfield(lua_State *L, int index, const char *k, int type, void *p) {
	if (!getfield(L, index, k))
		return 0;

	switch (type) {
	case LUA_TSTRING:
		*(const char **)p = luaL_checkstring(L, -1);
		break;
	case LUA_TNUMBER:
		*(lua_Number *)p = luaL_checknumber(L, -1);
		break;
	default:
		luaL_error(L, "loadfield(type=%d): invalid type", type);
		break;
	} /* switch() */

	lua_pop(L, 1); /* table keeps reference */

	return 1;
} /* loadfield() */


static const char *pushnid(lua_State *L, int nid) {
	const char *txt;
	ASN1_OBJECT *obj;
	char buf[256];
	int len;

	if ((txt = OBJ_nid2sn(nid)) || (txt = OBJ_nid2ln(nid))) {
		lua_pushstring(L, txt);
	} else {
		if (!(obj = OBJ_nid2obj(nid)))
			luaL_error(L, "%d: unknown ASN.1 NID", nid);

		if (-1 == (len = OBJ_obj2txt(buf, sizeof buf, obj, 1)))
			luaL_error(L, "%d: invalid ASN.1 NID", nid);

		lua_pushlstring(L, buf, len);
	}

	return lua_tostring(L, -1);
} /* pushnid() */


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
 * EVP_PKEY - openssl.pubkey
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int bio__gc(lua_State *L) {
	BIO **bio = lua_touserdata(L, 1);

	BIO_free(*bio);
	*bio = NULL;

	return 0;
} /* bio__gc() */

static BIO *getbio(lua_State *L) {
	BIO **bio;

	lua_pushcfunction(L, &bio__gc);
	lua_gettable(L, LUA_REGISTRYINDEX);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		bio = prepsimple(L, NULL, &bio__gc);

		if (!(*bio = BIO_new(BIO_s_mem())))
			throwssl(L, "BIO_new");

		lua_pushcfunction(L, &bio__gc);
		lua_pushvalue(L, -2);
		lua_settable(L, LUA_REGISTRYINDEX);
	}

	bio = lua_touserdata(L, -1);
	lua_pop(L, 1);

	BIO_reset(*bio);

	return *bio;
} /* getbio() */


static int pk_new(lua_State *L) {
	EVP_PKEY **ud;

	lua_settop(L, 1);

	ud = prepsimple(L, PUBKEY_CLASS);

	if (lua_istable(L, 1)) {
		int type = EVP_PKEY_RSA;
		unsigned bits = 1024;
		unsigned exp = 65537;
		int curve = NID_X9_62_prime192v1;
		const char *id;
		lua_Number n;

		if (!lua_istable(L, 1))
			goto creat;

		if (loadfield(L, 1, "type", LUA_TSTRING, &id)) {
			static const struct { int nid; const char *sn; } types[] = {
				{ EVP_PKEY_RSA, "RSA" },
				{ EVP_PKEY_DSA, "DSA" },
				{ EVP_PKEY_DH,  "DH" },
				{ EVP_PKEY_EC,  "EC" },
			};
			unsigned i;

			type = OBJ_sn2nid(id);

			if (NID_undef == (type = EVP_PKEY_type(OBJ_sn2nid(id)))) {
				for (i = 0; i < countof(types); i++) {
					if (strieq(id, types[i].sn)) {
						type = types[i].nid;
						break;
					}
				}
			}

			luaL_argcheck(L, type != NID_undef, 1, lua_pushfstring(L, "%s: invalid key type", id));
		}

		if (loadfield(L, 1, "bits", LUA_TNUMBER, &n)) {
			luaL_argcheck(L, n > 0 && n < UINT_MAX, 1, lua_pushfstring(L, "%f: `bits' invalid", n));
			bits = (unsigned)n;
		}

		if (loadfield(L, 1, "exp", LUA_TNUMBER, &n)) {
			luaL_argcheck(L, n > 0 && n < UINT_MAX, 1, lua_pushfstring(L, "%f: `exp' invalid", n));
			exp = (unsigned)n;
		}

		if (loadfield(L, 1, "curve", LUA_TSTRING, &id)) {
			curve = OBJ_sn2nid(id);
			luaL_argcheck(L, curve != NID_undef, 1, lua_pushfstring(L, "%s: invalid curve", id));
		}

creat:
		if (!(*ud = EVP_PKEY_new()))
			return throwssl(L, "pubkey.new");

		switch (EVP_PKEY_type(type)) {
		case EVP_PKEY_RSA: {
			RSA *rsa;

			if (!(rsa = RSA_generate_key(bits, exp, 0, 0)))
				return throwssl(L, "pubkey.new");

			EVP_PKEY_set1_RSA(*ud, rsa);

			RSA_free(rsa);

			break;
		}
		case EVP_PKEY_DSA: {
			DSA *dsa;

			if (!(dsa = DSA_generate_parameters(bits, 0, 0, 0, 0, 0, 0)))
				return throwssl(L, "pubkey.new");

			if (!DSA_generate_key(dsa)) {
				DSA_free(dsa);
				return throwssl(L, "pubkey.new");
			}

			EVP_PKEY_set1_DSA(*ud, dsa);

			DSA_free(dsa);

			break;
		}
		case EVP_PKEY_DH: {
			DH *dh;

			if (!(dh = DH_generate_parameters(bits, exp, 0, 0)))
				return throwssl(L, "pubkey.new");

			if (!DH_generate_key(dh)) {
				DH_free(dh);
				return throwssl(L, "pubkey.new");
			}

			EVP_PKEY_set1_DH(*ud, dh);

			DH_free(dh);

			break;
		}
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC: {
			EC_GROUP *grp;
			EC_KEY *key;

			if (!(grp = EC_GROUP_new_by_curve_name(curve)))
				return throwssl(L, "pubkey.new");

			EC_GROUP_set_asn1_flag(grp, OPENSSL_EC_NAMED_CURVE);

			/* compressed points patented */
			EC_GROUP_set_point_conversion_form(grp, POINT_CONVERSION_UNCOMPRESSED);

			if (!(key = EC_KEY_new())) {
				EC_GROUP_free(grp);
				return throwssl(L, "pubkey.new");
			}

			EC_KEY_set_group(key, grp);

			EC_GROUP_free(grp);

			if (!EC_KEY_generate_key(key)) {
				EC_KEY_free(key);
				return throwssl(L, "pubkey.new");
			}

			EVP_PKEY_set1_EC_KEY(*ud, key);

			EC_KEY_free(key);

			break;
		}
#endif
		default:
			return luaL_error(L, "%d: unknown EVP base type (%d)", EVP_PKEY_type(type), type);
		} /* switch() */
	} else {
		const char *pem;
		size_t len;
		BIO *bio;
		int ok;

		if (!(*ud = EVP_PKEY_new()))
			return throwssl(L, "pubkey.new");

		switch (lua_type(L, 1)) {
		case LUA_TSTRING:
			pem = luaL_checklstring(L, 1, &len);

			if (!(bio = BIO_new_mem_buf((void *)pem, len)))
				return throwssl(L, "pubkey.new");

			if (strstr(pem, "PUBLIC KEY")) {
				ok = !!PEM_read_bio_PUBKEY(bio, ud, 0, 0);
			} else {
				ok = !!PEM_read_bio_PrivateKey(bio, ud, 0, 0);
			}

			BIO_free(bio);

			if (!ok)
				return throwssl(L, "pubkey.new");

			break;
		default:
			return luaL_error(L, "%s: unknown key initializer", lua_typename(L, lua_type(L, 1)));
		} /* switch() */
	}

	return 1;
} /* pk_new() */


static int pk_interpose(lua_State *L) {
	return interpose(L, X509_NAME_CLASS);
} /* pk_interpose() */


static int pk_type(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PUBKEY_CLASS);
	int nid = key->type;

	pushnid(L, nid);

	return 1;
} /* pk_type() */


static int pk_setPublicKey(lua_State *L) {
	EVP_PKEY **key = luaL_checkudata(L, 1, PUBKEY_CLASS);
	const char *pem;
	size_t len;
	BIO *bio;
	int ok;

	lua_settop(L, 2);

	pem = luaL_checklstring(L, 2, &len);

	if (!(bio = BIO_new_mem_buf((void *)pem, len)))
		return throwssl(L, "pubkey.new");

	ok = !!PEM_read_bio_PUBKEY(bio, key, 0, 0);

	BIO_free(bio);

	if (!ok)
		return throwssl(L, "pubkey.new");

	lua_pushboolean(L, 1);

	return 1;
} /* pk_setPublicKey() */


static int pk_setPrivateKey(lua_State *L) {
	EVP_PKEY **key = luaL_checkudata(L, 1, PUBKEY_CLASS);
	const char *pem;
	size_t len;
	BIO *bio;
	int ok;

	lua_settop(L, 2);

	pem = luaL_checklstring(L, 2, &len);

	if (!(bio = BIO_new_mem_buf((void *)pem, len)))
		return throwssl(L, "pubkey.new");

	ok = !!PEM_read_bio_PrivateKey(bio, key, 0, 0);

	BIO_free(bio);

	if (!ok)
		return throwssl(L, "pubkey.new");

	lua_pushboolean(L, 1);

	return 1;
} /* pk_setPrivateKEY() */


static int pk_sign(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PUBKEY_CLASS);
	EVP_MD_CTX *md = luaL_checkudata(L, 2, DIGEST_CLASS);
	luaL_Buffer B;
	unsigned n;

	if (LUAL_BUFFERSIZE < EVP_PKEY_size(key))
		return luaL_error(L, "pubkey:sign: LUAL_BUFFERSIZE(%u) < EVP_PKEY_size(%u)", (unsigned)LUAL_BUFFERSIZE, (unsigned)EVP_PKEY_size(key));

	luaL_buffinit(L, &B);
	n = LUAL_BUFFERSIZE;

	if (!EVP_SignFinal(md, (void *)luaL_prepbuffer(&B), &n, key))
		return throwssl(L, "pubkey:sign");

	luaL_addsize(&B, n);
	luaL_pushresult(&B);

	return 1;
} /* pk_sign() */


static int pk_verify(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PUBKEY_CLASS);
	size_t len;
	const void *sig = luaL_checklstring(L, 2, &len);
	EVP_MD_CTX *md = luaL_checkudata(L, 3, DIGEST_CLASS);

	switch (EVP_VerifyFinal(md, sig, len, key)) {
	case 0: /* WRONG */
		ERR_clear_error();
		lua_pushboolean(L, 0);

		break;
	case 1: /* OK */
		lua_pushboolean(L, 1);

		break;
	default:
		return throwssl(L, "pubkey:verify");
	}

	return 1;
} /* pk_verify() */


static int pk_toPEM(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PUBKEY_CLASS);
	int top, i, ok;
	BIO *bio;
	char *pem;
	long len;

	if (1 == (top = lua_gettop(L))) {
		lua_pushstring(L, "publickey");
		++top;
	}

	bio = getbio(L);

	for (i = 2; i <= top; i++) {
		static const char *opts[] = {
			"public", "PublicKey",
			"private", "PrivateKey",
//			"params", "Parameters",
		};

		switch (checkoption(L, i, NULL, opts)) {
		case 0: case 1:
			if (!PEM_write_bio_PUBKEY(bio, key))
				return throwssl(L, "pubkey:__tostring");

			len = BIO_get_mem_data(bio, &pem);
			lua_pushlstring(L, pem, len);

			BIO_reset(bio);
			break;
		case 2: case 3:
			if (!PEM_write_bio_PrivateKey(bio, key, 0, 0, 0, 0, 0))
				throwssl(L, "pubkey:__tostring");

			len = BIO_get_mem_data(bio, &pem);
			lua_pushlstring(L, pem, len);

			break;
		case 4: case 5:
			/* EVP_PKEY_base_id not in OS X */
			switch (EVP_PKEY_type(key->type)) {
			case EVP_PKEY_RSA:
				break;
			case EVP_PKEY_DSA: {
				DSA *dsa = EVP_PKEY_get1_DSA(key);

				ok = !!PEM_write_bio_DSAparams(bio, dsa);

				DSA_free(dsa);

				if (!ok)
					return throwssl(L, "pubkey:__tostring");

				break;
			}
			case EVP_PKEY_DH: {
				DH *dh = EVP_PKEY_get1_DH(key);

				ok = !!PEM_write_bio_DHparams(bio, dh);

				DH_free(dh);

				if (!ok)
					return throwssl(L, "pubkey:__tostring");

				break;
			}
#ifndef OPENSSL_NO_EC
			case EVP_PKEY_EC: {
				EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
				const EC_GROUP *grp = EC_KEY_get0_group(ec);

				ok = !!PEM_write_bio_ECPKParameters(bio, grp);

				EC_KEY_free(ec);

				if (!ok)
					return throwssl(L, "pubkey:__tostring");

				break;
			}
#endif
			default:
				return luaL_error(L, "%d: unknown EVP base type", EVP_PKEY_type(key->type));
			}

			lua_pushlstring(L, pem, len);

			BIO_reset(bio);

			break;
		default:
			lua_pushnil(L);

			break;
		} /* switch() */
	} /* for() */

	return lua_gettop(L) - top;
} /* pk_toPEM() */


static int pk__tostring(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PUBKEY_CLASS);
	BIO *bio = getbio(L);
	char *pem;
	long len;
	int ok;

	if (!PEM_write_bio_PUBKEY(bio, key))
		return throwssl(L, "pubkey:__tostring");

	len = BIO_get_mem_data(bio, &pem);
	lua_pushlstring(L, pem, len);

	return 1;
} /* pk__tostring() */


static int pk__gc(lua_State *L) {
	EVP_PKEY **ud = luaL_checkudata(L, 1, PUBKEY_CLASS);

	EVP_PKEY_free(*ud);
	*ud = NULL;

	return 0;
} /* pk__gc() */


static const luaL_Reg pk_methods[] = {
	{ "type",          &pk_type },
	{ "setPublicKey",  &pk_setPublicKey },
	{ "setPrivateKey", &pk_setPrivateKey },
	{ "sign",          &pk_sign },
	{ "verify",        &pk_verify },
	{ "toPEM",         &pk_toPEM },
	{ NULL,            NULL },
};

static const luaL_Reg pk_metatable[] = {
	{ "__tostring", &pk__tostring },
	{ "__gc",       &pk__gc },
	{ NULL,         NULL },
};


static const luaL_Reg pk_globals[] = {
	{ "new",       &pk_new },
	{ "interpose", &pk_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_pubkey(lua_State *L) {
	initall(L);

	luaL_newlib(L, pk_globals);

	return 1;
} /* luaopen__openssl_pubkey() */


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


static int xn__next(lua_State *L) {
	X509_NAME *name = checksimple(L, lua_upvalueindex(1), X509_NAME_CLASS);
	X509_NAME_ENTRY *entry;
	ASN1_OBJECT *obj;
	const char *id;
	char txt[256];
	int i, n, nid, len;

	lua_settop(L, 0);

	i = lua_tointeger(L, lua_upvalueindex(2));
	n = X509_NAME_entry_count(name);

	while (i < n) {
		if (!(entry = X509_NAME_get_entry(name, i++)))
			continue;

		obj = X509_NAME_ENTRY_get_object(entry);
		nid = OBJ_obj2nid(obj);

		if (nid != NID_undef && ((id = OBJ_nid2sn(nid)) || (id = OBJ_nid2ln(nid)))) {
			lua_pushstring(L, id);
		} else {
			if (0 > (len = OBJ_obj2txt(txt, sizeof txt, obj, 1)))
				return throwssl(L, "x509.name:__pairs");

			lua_pushlstring(L, txt, len);
		}

		len = ASN1_STRING_length(X509_NAME_ENTRY_get_data(entry));
		lua_pushlstring(L, (char *)ASN1_STRING_data(X509_NAME_ENTRY_get_data(entry)), len);

		break;
	}

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* xn__next() */

static int xn__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);

	lua_pushcclosure(L, &xn__next, 2);

	return 1;
} /* xn__pairs() */


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
	{ "__pairs",    &xn__pairs },
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

	if (!(*ud = sk_GENERAL_NAME_dup(gens)))
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
			tag = "email";
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
	int format = luaL_checkoption(L, 3, "x", (const char *[]){ "s", "x", "n", NULL });
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

#if LUA_VERSION_NUM < 502
		luaL_buffinit(L, &B);
#else
		luaL_buffinitsize(L, &B, 2 * len);
#endif

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

	if (!(name = X509_get_issuer_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xc_getIssuer() */


static int xc_setIssuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_issuer_name(crt, name))
		return throwssl(L, "x509.cert:setIssuer");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuer() */


static int xc_getSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;

	if (!(name = X509_get_subject_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xc_getSubject() */


static int xc_setSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_subject_name(crt, name))
		return throwssl(L, "x509.cert:setSubject");

	lua_pushboolean(L, 1);

	return 1;
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


static int xc_getBasicConstraint(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BASIC_CONSTRAINTS *bs;
	int CA, pathLen;

	if (!(bs = X509_get_ext_d2i(crt, NID_basic_constraints, 0, 0))) {
		/* FIXME: detect error or just non-existent */

		if (lua_gettop(L) > 1)
			return 0;

		lua_newtable(L);

		return 1;
	}

	CA = bs->ca;
	pathLen = ASN1_INTEGER_get(bs->pathlen);

	BASIC_CONSTRAINTS_free(bs);

	if (lua_gettop(L) > 1) {
		int n = 0, i, top;

		for (i = 2, top = lua_gettop(L); i <= top; i++) {
			switch (checkoption(L, i, 0, (const char *[]){ "CA", "pathLen", "pathLenConstraint", 0 })) {
			case 0:
				lua_pushboolean(L, CA);
				n++;
				break;
			case 1:
				/* FALL THROUGH */
			case 2:
				lua_pushinteger(L, pathLen);
				n++;
				break;
			}
		}

		return n;
	} else {
		lua_newtable(L);

		lua_pushboolean(L, CA);
		lua_setfield(L, -2, "CA");

		lua_pushinteger(L, pathLen);
		lua_setfield(L, -2, "pathLen");

		return 1;
	}
} /* xc_getBasicConstraint() */


static int xc_setBasicConstraint(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BASIC_CONSTRAINTS *bs = 0;
	int CA = -1, pathLen = -1;
	int critical = 0;

	luaL_checkany(L, 2);

	if (lua_istable(L, 2)) {
		lua_getfield(L, 2, "CA");
		if (!lua_isnil(L, -1))
			CA = lua_toboolean(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, 2, "pathLen");
		pathLen = luaL_optint(L, -1, pathLen);
		lua_pop(L, 1);

		lua_getfield(L, 2, "pathLenConstraint");
		pathLen = luaL_optint(L, -1, pathLen);
		lua_pop(L, 1);

		if (!(bs = BASIC_CONSTRAINTS_new()))
			goto error;
	} else {
		lua_settop(L, 3);

		switch (checkoption(L, 2, 0, (const char *[]){ "CA", "pathLen", "pathLenConstraint", 0 })) {
		case 0:
			luaL_checktype(L, 3, LUA_TBOOLEAN);
			CA = lua_toboolean(L, 3);

			break;
		case 1:
			/* FALL THROUGH */
		case 2:
			pathLen = luaL_checkint(L, 3);

			break;
		}

		if (!(bs = X509_get_ext_d2i(crt, NID_basic_constraints, &critical, 0))) {
			/* FIXME: detect whether error or just non-existent */
			if (!(bs = BASIC_CONSTRAINTS_new()))
				goto error;
		}
	}

	if (CA != -1)
		bs->ca = CA;

	if (pathLen >= 0) {
		ASN1_INTEGER_free(bs->pathlen);

		if (!(bs->pathlen = M_ASN1_INTEGER_new()))
			goto error;

		if (!ASN1_INTEGER_set(bs->pathlen, pathLen))
			goto error;
	}

	if (!X509_add1_ext_i2d(crt, NID_basic_constraints, bs, critical, X509V3_ADD_REPLACE))
		goto error;

	BASIC_CONSTRAINTS_free(bs);

	lua_pushboolean(L, 1);

	return 1;
error:
	BASIC_CONSTRAINTS_free(bs);

	return throwssl(L, "x509.cert:setBasicConstraint");
} /* xc_setBasicConstraint() */


static int xc_getBasicConstraintsCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_basic_constraints));

	return 1;
} /* xc_getBasicConstraintsCritical() */


static int xc_setBasicConstraintsCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_basic_constraints, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setBasicConstraintsCritical() */


static int xc_isIssuedBy(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509 *issuer = checksimple(L, 2, X509_CERT_CLASS);
	EVP_PKEY *key;
	int ok, why = 0;

	ERR_clear_error();

	if (X509_V_OK != (why = X509_check_issued(issuer, crt)))
		goto done;

	if (!(key = X509_get_pubkey(issuer))) {
		why = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
		goto done;
	}

	ok = (1 == X509_verify(crt, key));

	EVP_PKEY_free(key);

	if (!ok)
		why = X509_V_ERR_CERT_SIGNATURE_FAILURE;

done:
	if (why != X509_V_OK) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, X509_verify_cert_error_string(why));

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* xc_isIssuedBy() */


static int xc_getPublicKey(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY **key = prepsimple(L, PUBKEY_CLASS);

	if (!(*key = X509_get_pubkey(crt)))
		return throwssl(L, "x509.cert:getPublicKey");

	return 1;
} /* xc_getPublicKey() */


static int xc_setPublicKey(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PUBKEY_CLASS);

	if (!X509_set_pubkey(crt, key))
		return throwssl(L, "x509.cert:setPublicKey");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setPublicKey() */


static const EVP_MD *xc_signature(lua_State *L, int index, EVP_PKEY *key) {
	const char *id;
	const EVP_MD *md;

	if ((id = luaL_optstring(L, index, NULL)))
		return ((md = EVP_get_digestbyname(id)))? md : EVP_md_null();

	switch (EVP_PKEY_type(key->type)) {
	case EVP_PKEY_RSA:
		return EVP_sha1();
	case EVP_PKEY_DSA:
		return EVP_dss1();
	case EVP_PKEY_EC:
		return EVP_ecdsa();
	default:
		return EVP_md_null();
	}
} /* xc_signature() */

static int xc_sign(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PUBKEY_CLASS);

	if (!X509_sign(crt, key, xc_signature(L, 3, key)))
		return throwssl(L, "x509.cert:sign");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_sign() */


static int xc__tostring(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int fmt = checkoption(L, 2, "pem", (const char *[]){ "pem", 0 });
	BIO *bio = getbio(L);
	char *pem;
	long len;

	if (!PEM_write_bio_X509(bio, crt))
		return throwssl(L, "x509.cert:__tostring");

	len = BIO_get_mem_data(bio, &pem);

	lua_pushlstring(L, pem, len);

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
	{ "getBasicConstraints", &xc_getBasicConstraint },
	{ "getBasicConstraint",  &xc_getBasicConstraint },
	{ "setBasicConstraints", &xc_setBasicConstraint },
	{ "setBasicConstraint",  &xc_setBasicConstraint },
	{ "getBasicConstraintsCritical", &xc_getBasicConstraintsCritical },
	{ "setBasicConstraintsCritical", &xc_setBasicConstraintsCritical },
	{ "isIssuedBy",    &xc_isIssuedBy },
	{ "getPublicKey",  &xc_getPublicKey },
	{ "setPublicKey",  &xc_setPublicKey },
	{ "sign",          &xc_sign },
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


/*
 * X509_REQ - openssl.x509.csr
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xr_new(lua_State *L) {
	const char *pem;
	size_t len;
	X509_REQ **ud;
	X509 *crt;

	lua_settop(L, 1);

	ud = prepsimple(L, X509_CSR_CLASS);

	if ((crt = testsimple(L, 1, X509_CERT_CLASS))) {
		if (!(*ud = X509_to_X509_REQ(crt, 0, 0)))
			return throwssl(L, "x509.csr.new");
	} else if ((pem = luaL_optlstring(L, 1, NULL, &len))) {
		BIO *tmp;
		int ok;

		if (!(tmp = BIO_new_mem_buf((char *)pem, len)))
			return throwssl(L, "x509.csr.new");

		ok = !!PEM_read_bio_X509_REQ(tmp, ud, 0, ""); /* no password */

		BIO_free(tmp);

		if (!ok)
			return throwssl(L, "x509.csr.new");
	} else {
		if (!(*ud = X509_REQ_new()))
			return throwssl(L, "x509.csr.new");
	}

	return 1;
} /* xr_new() */


static int xr_interpose(lua_State *L) {
	return interpose(L, X509_CSR_CLASS);
} /* xr_interpose() */


static int xr_getVersion(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);

	lua_pushinteger(L, X509_REQ_get_version(csr) + 1);

	return 1;
} /* xr_getVersion() */


static int xr_setVersion(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	int version = luaL_checkint(L, 2);

	if (!X509_REQ_set_version(csr, version - 1))
		return luaL_error(L, "x509.csr:setVersion: %d: invalid version", version);

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setVersion() */


static int xr_getSubject(lua_State *L) {
	X509_REQ *crt = checksimple(L, 1, X509_CSR_CLASS);
	X509_NAME *name;

	if (!(name = X509_REQ_get_subject_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xr_getSubject() */


static int xr_setSubject(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_REQ_set_subject_name(csr, name))
		return throwssl(L, "x509.csr:setSubject");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setSubject() */


static int xr_getPublicKey(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY **key = prepsimple(L, PUBKEY_CLASS);

	if (!(*key = X509_REQ_get_pubkey(csr)))
		return throwssl(L, "x509.cert:getPublicKey");

	return 1;
} /* xr_getPublicKey() */


static int xr_setPublicKey(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PUBKEY_CLASS);

	if (!X509_REQ_set_pubkey(csr, key))
		return throwssl(L, "x509.csr:setPublicKey");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setPublicKey() */


static int xr_sign(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PUBKEY_CLASS);

	if (!X509_REQ_sign(csr, key, xc_signature(L, 3, key)))
		return throwssl(L, "x509.csr:sign");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_sign() */


static int xr__tostring(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	int fmt = checkoption(L, 2, "pem", (const char *[]){ "pem", 0 });
	BIO *bio = getbio(L);
	char *pem;
	long len;

	if (!PEM_write_bio_X509_REQ(bio, csr))
		return throwssl(L, "x509.csr:__tostring");

	len = BIO_get_mem_data(bio, &pem);

	lua_pushlstring(L, pem, len);

	return 1;
} /* xr__tostring() */


static int xr__gc(lua_State *L) {
	X509_REQ **ud = luaL_checkudata(L, 1, X509_CSR_CLASS);

	X509_REQ_free(*ud);
	*ud = NULL;

	return 0;
} /* xr__gc() */

static const luaL_Reg xr_methods[] = {
	{ "getVersion",   &xr_getVersion },
	{ "setVersion",   &xr_setVersion },
	{ "getSubject",   &xr_getSubject },
	{ "setSubject",   &xr_setSubject },
	{ "getPublicKey", &xr_getPublicKey },
	{ "setPublicKey", &xr_setPublicKey },
	{ "sign",         &xr_sign },
	{ NULL,           NULL },
};

static const luaL_Reg xr_metatable[] = {
	{ "__tostring", &xr__tostring },
	{ "__gc",       &xr__gc },
	{ NULL,         NULL },
};


static const luaL_Reg xr_globals[] = {
	{ "new",       &xr_new },
	{ "interpose", &xr_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_csr(lua_State *L) {
	initall(L);

	luaL_newlib(L, xr_globals);

	return 1;
} /* luaopen__openssl_x509_csr() */


/*
 * STACK_OF(X509) - openssl.x509.chain
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void xl_dup(lua_State *L, STACK_OF(X509) *src, _Bool copy) {
	STACK_OF(X509) **dst = prepsimple(L, X509_CHAIN_CLASS);
	X509 *crt;
	int i, n;

	if (copy) {
		if (!(*dst = sk_X509_new_null()))
			goto error;

		n = sk_X509_num(src);

		for (i = 0; i < n; i++) {
			if (!(crt = sk_X509_value(src, i)))
				continue;

			if (!(crt = X509_dup(crt)))
				goto error;

			if (!sk_X509_push(*dst, crt)) {
				X509_free(crt);
				goto error;
			}
		}
	} else {
		if (!(*dst = sk_X509_dup(src)))
			goto error;

		n = sk_X509_num(*dst);

		for (i = 0; i < n; i++) {
			if (!(crt = sk_X509_value(*dst, i)))
				continue;
			CRYPTO_add(&crt->references, 1, CRYPTO_LOCK_X509);
		}
	}

	return;
error:
	throwssl(L, "sk_X509_dup");
} /* xl_dup() */


static int xl_new(lua_State *L) {
	STACK_OF(X509) **chain = prepsimple(L, X509_CHAIN_CLASS);

	if (!(*chain = sk_X509_new_null()))
		return throwssl(L, "x509.chain.new");

	return 1;
} /* xl_new() */


static int xl_interpose(lua_State *L) {
	return interpose(L, X509_CHAIN_CLASS);
} /* xl_interpose() */


static int xl_add(lua_State *L) {
	STACK_OF(X509) *chain = checksimple(L, 1, X509_CHAIN_CLASS);
	X509 *crt = checksimple(L, 2, X509_CERT_CLASS);
	X509 *dup;

	if (!(dup = X509_dup(crt)))
		return throwssl(L, "x509.chain:add");

	if (!sk_X509_push(chain, dup)) {
		X509_free(dup);
		return throwssl(L, "x509.chain:add");
	}

	lua_pushboolean(L, 1);

	return 1;
} /* xl_add() */


static int xl__next(lua_State *L) {
	STACK_OF(X509) *chain = checksimple(L, lua_upvalueindex(1), X509_CHAIN_CLASS);
	int i = lua_tointeger(L, lua_upvalueindex(2));
	int n = sk_X509_num(chain);

	lua_settop(L, 0);

	while (i < n) {
		X509 *crt, **ret;

		if (!(crt = sk_X509_value(chain, i++)))
			continue;

		lua_pushinteger(L, i);

		ret = prepsimple(L, X509_CERT_CLASS);

		if (!(*ret = X509_dup(crt)))
			return throwssl(L, "x509.chain:__next");

		break;
	}

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* xl__next() */

static int xl__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, &xl__next, 2);

	return 1;
} /* xl__pairs() */


static int xl__gc(lua_State *L) {
	STACK_OF(X509) **chain = luaL_checkudata(L, 1, X509_CHAIN_CLASS);

	sk_X509_pop_free(*chain, X509_free);
	*chain = NULL;

	return 0;
} /* xl__gc() */


static const luaL_Reg xl_methods[] = {
	{ "add", &xl_add },
	{ NULL,  NULL },
};

static const luaL_Reg xl_metatable[] = {
	{ "__pairs",  &xl__pairs },
	{ "__ipairs", &xl__pairs },
	{ "__gc",     &xl__gc },
	{ NULL,       NULL },
};

static const luaL_Reg xl_globals[] = {
	{ "new",       &xl_new },
	{ "interpose", &xl_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_chain(lua_State *L) {
	initall(L);

	luaL_newlib(L, xl_globals);

	return 1;
} /* luaopen__openssl_x509_chain() */


/*
 * X509_STORE - openssl.x509.store
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xs_new(lua_State *L) {
	X509_STORE **ud = prepsimple(L, X509_STORE_CLASS);

	if (!(*ud = X509_STORE_new()))
		return throwssl(L, "x509.store");

	return 1;
} /* xs_new() */


static int xs_interpose(lua_State *L) {
	return interpose(L, X509_STORE_CLASS);
} /* xs_interpose() */


static int xs_add(lua_State *L) {
	X509_STORE *store = checksimple(L, 1, X509_STORE_CLASS);
	int i, top = lua_gettop(L);

	for (i = 2; i <= top; i++) {
		if (lua_isuserdata(L, i)) {
			X509 *crt = checksimple(L, i, X509_CERT_CLASS);
			X509 *dup;

			if (!(dup = X509_dup(crt)))
				return throwssl(L, "x509.store:add");

			if (!X509_STORE_add_cert(store, dup)) {
				X509_free(dup);
				return throwssl(L, "x509.store:add");
			}
		} else {
			const char *path = luaL_checkstring(L, i);
			struct stat st;
			int ok;

			if (0 != stat(path, &st))
				return luaL_error(L, "%s: %s", path, strerror(errno));

			if (S_ISDIR(st.st_mode))
				ok = X509_STORE_load_locations(store, NULL, path);
			else
				ok = X509_STORE_load_locations(store, path, NULL);

			if (!ok)
				return throwssl(L, "x509.store:add");
		}
	}

	lua_pushboolean(L, 1);

	return 1;
} /* xs_add() */


static int xs_verify(lua_State *L) {
	X509_STORE *store = checksimple(L, 1, X509_STORE_CLASS);
	X509 *crt = checksimple(L, 2, X509_CERT_CLASS);
	STACK_OF(X509) *chain = NULL, **proof;
	X509_STORE_CTX ctx;
	int ok, why;

	/* pre-allocate space for a successful return */
	lua_settop(L, 3);
	proof = prepsimple(L, X509_CHAIN_CLASS);

	if (!lua_isnoneornil(L, 3)) {
		X509 *elm;
		int i, n;

		if (!(chain = sk_X509_dup(checksimple(L, 3, X509_CHAIN_CLASS))))
			return throwssl(L, "x509.store:verify");

		n = sk_X509_num(chain);

		for (i = 0; i < n; i++) {
			if (!(elm = sk_X509_value(chain, i)))
				continue;
			CRYPTO_add(&elm->references, 1, CRYPTO_LOCK_X509);
		}
	}

	if (!X509_STORE_CTX_init(&ctx, store, crt, chain)) {
		sk_X509_pop_free(chain, X509_free);
		return throwssl(L, "x509.store:verify");
	}

	ERR_clear_error();

	ok = X509_verify_cert(&ctx);

	switch (ok) {
	case 1: /* verified */
		*proof = X509_STORE_CTX_get1_chain(&ctx);

		X509_STORE_CTX_cleanup(&ctx);

		if (!*proof)
			return throwssl(L, "x509.store:verify");

		lua_pushboolean(L, 1);
		lua_pushvalue(L, -2);

		return 2;
	case 0: /* not verified */
		why = X509_STORE_CTX_get_error(&ctx);

		X509_STORE_CTX_cleanup(&ctx);

		lua_pushboolean(L, 0);
		lua_pushstring(L, X509_verify_cert_error_string(why));

		return 2;
	default:
		X509_STORE_CTX_cleanup(&ctx);

		return throwssl(L, "x509.store:verify");
	}
} /* xs_verify() */


static int xs__gc(lua_State *L) {
	X509_STORE **ud = luaL_checkudata(L, 1, X509_STORE_CLASS);

	X509_STORE_free(*ud);
	*ud = NULL;

	return 0;
} /* xs__gc() */


static const luaL_Reg xs_methods[] = {
	{ "add",    &xs_add },
	{ "verify", &xs_verify },
	{ NULL,     NULL },
};

static const luaL_Reg xs_metatable[] = {
	{ "__gc", &xs__gc },
	{ NULL,   NULL },
};

static const luaL_Reg xs_globals[] = {
	{ "new",       &xs_new },
	{ "interpose", &xs_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_store(lua_State *L) {
	initall(L);

	luaL_newlib(L, xs_globals);

	return 1;
} /* luaopen__openssl_x509_store() */


/*
 * X509_STORE_CTX - openssl.x509.store.context
 *
 * This object is intended to be a temporary container in OpenSSL, so the
 * memory management is quite clumsy. In particular, it doesn't take
 * ownership of the X509_STORE object, which means the reference must be
 * held externally for the life of the X509_STORE_CTX object.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#if 0
static int stx_new(lua_State *L) {
	X509_STORE_CTX **ud = prepsimple(L, X509_STCTX_CLASS);
	STACK_OF(X509) *chain;

	if (!(*ud = X509_STORE_CTX_new()))
		return throwssl(L, "x509.store.context");

	return 1;
} /* stx_new() */


static int stx_interpose(lua_State *L) {
	return interpose(L, X509_STCTX_CLASS);
} /* stx_interpose() */


static int stx_add(lua_State *L) {
	X509_STORE_CTX *ctx = checksimple(L, 1, X509_STCTX_CLASS);

	return 0;
} /* stx_add() */


static int stx__gc(lua_State *L) {
	X509_STORE **ud = luaL_checkudata(L, 1, X509_STORE_CLASS);

	X509_STORE_free(*ud);
	*ud = NULL;

	return 0;
} /* stx__gc() */


static const luaL_Reg stx_methods[] = {
	{ "add", &stx_add },
	{ NULL,  NULL },
};

static const luaL_Reg stx_metatable[] = {
	{ "__gc", &stx__gc },
	{ NULL,   NULL },
};

static const luaL_Reg stx_globals[] = {
	{ "new",       &stx_new },
	{ "interpose", &stx_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_x509_store_context(lua_State *L) {
	initall(L);

	luaL_newlib(L, stx_globals);

	return 1;
} /* luaopen__openssl_x509_store_context() */
#endif


/*
 * SSL_CTX - openssl.ssl.context
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int sx_new(lua_State *L) {
	static const char *opts[] = {
		"SSLv2", "SSLv3", "SSLv23", "SSL", "TLSv1", "TLS", NULL
	};
	/* later versions of SSL declare a const qualifier on the return type */
	__typeof__(&TLSv1_client_method) method = &TLSv1_client_method;
	_Bool srv;
	SSL_CTX **ud;

	lua_settop(L, 2);
	srv = lua_toboolean(L, 2);

	switch (checkoption(L, 1, "TLS", opts)) {
#ifndef OPENSSL_NO_SSL2
	case 0: /* SSLv2 */
		method = (srv)? &SSLv2_server_method : &SSLv2_client_method;
		break;
#endif
	case 1: /* SSLv3 */
		method = (srv)? &SSLv3_server_method : &SSLv3_client_method;
		break;
	case 2: /* SSLv23 */
		/* FALL THROUGH */
	case 3: /* SSL */
		method = (srv)? &SSLv23_server_method : &SSLv23_client_method;
		break;
	case 4: /* TLSv1 */
		/* FALL THROUGH */
	case 5: /* TLS */
		method = (srv)? &TLSv1_server_method : &TLSv1_client_method;
		break;
	}

	ud = prepsimple(L, SSL_CTX_CLASS);

	if (!(*ud = SSL_CTX_new(method())))
		return throwssl(L, "ssl.context.new");

	return 1;
} /* sx_new() */


static int sx_interpose(lua_State *L) {
	return interpose(L, SSL_CTX_CLASS);
} /* sx_interpose() */


static int sx_setStore(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509_STORE *store = checksimple(L, 2, X509_STORE_CLASS);

	SSL_CTX_set_cert_store(ctx, store);
	CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setStore() */


static int sx_setVerify(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int mode = luaL_optint(L, 2, -1);
	int depth = luaL_optint(L, 3, -1);

	if (mode != -1)
		SSL_CTX_set_verify(ctx, mode, 0);

	if (depth != -1)
		SSL_CTX_set_verify_depth(ctx, depth);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setVerify() */


static int sx_getVerify(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	lua_pushinteger(L, SSL_CTX_get_verify_mode(ctx));
	lua_pushinteger(L, SSL_CTX_get_verify_depth(ctx));

	return 2;
} /* sx_getVerify() */


static int sx_setCertificate(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509 *crt = X509_dup(checksimple(L, 2, X509_CERT_CLASS));
	int ok;

	ok = SSL_CTX_use_certificate(ctx, crt);
	X509_free(crt);

	if (!ok)
		return throwssl(L, "ssl.context:setCertificate");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCertificate() */


static int sx_setPrivateKey(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PUBKEY_CLASS);

	/*
	 * NOTE: No easy way to dup the key, but a shared reference should
	 * be okay as keys are less mutable than certificates.
	 */
	if (!SSL_CTX_use_PrivateKey(ctx, key))
		return throwssl(L, "ssl.context:setPrivateKey");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setPrivateKey() */


static int sx_setCipherList(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	const char *ciphers = luaL_checkstring(L, 2);

	if (!SSL_CTX_set_cipher_list(ctx, ciphers))
		return throwssl(L, "ssl.context:setCipherList");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCipherList() */


static int sx__gc(lua_State *L) {
	SSL_CTX **ud = luaL_checkudata(L, 1, SSL_CTX_CLASS);

	SSL_CTX_free(*ud);
	*ud = NULL;

	return 0;
} /* sx__gc() */


static const luaL_Reg sx_methods[] = {
	{ "setStore",  &sx_setStore },
	{ "setVerify", &sx_setVerify },
	{ "getVerify", &sx_getVerify },
	{ "setCertificate", &sx_setCertificate },
	{ "setPrivateKey", &sx_setPrivateKey },
	{ "setCipherList", &sx_setCipherList },
	{ NULL, NULL },
};

static const luaL_Reg sx_metatable[] = {
	{ "__gc", &sx__gc },
	{ NULL,   NULL },
};

static const luaL_Reg sx_globals[] = {
	{ "new",       &sx_new },
	{ "interpose", &sx_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_ssl_context(lua_State *L) {
	initall(L);

	luaL_newlib(L, sx_globals);

	lua_pushinteger(L, SSL_VERIFY_NONE);
	lua_setfield(L, -2, "VERIFY_NONE");

	lua_pushinteger(L, SSL_VERIFY_PEER);
	lua_setfield(L, -2, "VERIFY_PEER");

	lua_pushinteger(L, SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	lua_setfield(L, -2, "VERIFY_FAIL_IF_NO_PEER_CERT");

	lua_pushinteger(L, SSL_VERIFY_CLIENT_ONCE);
	lua_setfield(L, -2, "VERIFY_CLIENT_ONCE");

	return 1;
} /* luaopen__openssl_ssl_context() */


/*
 * SSL - openssl.ssl
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int ssl_new(lua_State *L) {
	lua_pushnil(L);

	return 1;
} /* ssl_new() */


static int ssl_interpose(lua_State *L) {
	return interpose(L, SSL_CLASS);
} /* ssl_interpose() */


static int ssl_getPeerCertificate(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509 **x509 = prepsimple(L, X509_CERT_CLASS);

	if (!(*x509 = SSL_get_peer_certificate(ssl)))
		return 0;

	return 1;
} /* ssl_getPeerCertificate() */


static int ssl_getPeerChain(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	STACK_OF(X509) *chain;

	if (!(chain = SSL_get_peer_cert_chain(ssl)))
		return 0;

	xl_dup(L, chain, 0);

	return 1;
} /* ssl_getPeerChain() */


static int ssl_getCipherInfo(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const SSL_CIPHER *cipher;
	char descr[256];

	if (!(cipher = SSL_get_current_cipher(ssl)))
		return 0;

	lua_newtable(L);

	lua_pushstring(L, SSL_CIPHER_get_name(cipher));
	lua_setfield(L, -2, "name");

	lua_pushinteger(L, SSL_CIPHER_get_bits(cipher, 0));
	lua_setfield(L, -2, "bits");

	lua_pushstring(L, SSL_CIPHER_get_version(cipher));
	lua_setfield(L, -2, "version");

	lua_pushstring(L, SSL_CIPHER_description(cipher, descr, sizeof descr));
	lua_setfield(L, -2, "description");

	return 1;
} /* ssl_getCipherInfo() */


static int ssl__gc(lua_State *L) {
	SSL **ud = luaL_checkudata(L, 1, SSL_CLASS);

	SSL_free(*ud);
	*ud = NULL;

	return 0;
} /* ssl__gc() */


static const luaL_Reg ssl_methods[] = {
	{ "getPeerCertificate", &ssl_getPeerCertificate },
	{ "getPeerChain",       &ssl_getPeerChain },
	{ "getCipherInfo",      &ssl_getCipherInfo },
	{ NULL,                 NULL },
};

static const luaL_Reg ssl_metatable[] = {
	{ "__gc", &ssl__gc },
	{ NULL,   NULL },
};

static const luaL_Reg ssl_globals[] = {
	{ "new",       &ssl_new },
	{ "interpose", &ssl_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_ssl(lua_State *L) {
	initall(L);

	luaL_newlib(L, ssl_globals);

	return 1;
} /* luaopen__openssl_ssl() */


/*
 * Digest - openssl.digest
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const EVP_MD *md_optdigest(lua_State *L, int index) {
	const char *name = luaL_optstring(L, index, "sha1");
	const EVP_MD *type;

	if (!(type = EVP_get_digestbyname(name)))
		luaL_argerror(L, index, lua_pushfstring(L, "%s: invalid digest type", name));

	return type;
} /* md_optdigest() */


static int md_new(lua_State *L) {
	const EVP_MD *type = md_optdigest(L, 1);
	EVP_MD_CTX *ctx;

	ctx = prepudata(L, sizeof *ctx, DIGEST_CLASS, NULL);

	EVP_MD_CTX_init(ctx);

	if (!EVP_DigestInit_ex(ctx, type, NULL))
		return throwssl(L, "digest.new");

	return 1;
} /* md_new() */


static int md_interpose(lua_State *L) {
	return interpose(L, DIGEST_CLASS);
} /* md_interpose() */


static int md_update(lua_State *L) {
	EVP_MD_CTX *ctx = luaL_checkudata(L, 1, DIGEST_CLASS);
	int i, top = lua_gettop(L);

	for (i = 2; i < top; i++) {
		const void *p;
		size_t n;

		p = luaL_checklstring(L, i, &n);

		if (!EVP_DigestUpdate(ctx, p, n))
			return throwssl(L, "digest:update");
	}

	lua_pushboolean(L, 1);
	
	return 1;
} /* md_update() */


static int md_final(lua_State *L) {
	EVP_MD_CTX *ctx = luaL_checkudata(L, 1, DIGEST_CLASS);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len;

	if (!EVP_DigestFinal_ex(ctx, md, &len))
		return throwssl(L, "digest:final");

	lua_pushlstring(L, (char *)md, len);

	return 1;
} /* md_final() */


static int md__gc(lua_State *L) {
	EVP_MD_CTX *ctx = luaL_checkudata(L, 1, DIGEST_CLASS);

	EVP_MD_CTX_cleanup(ctx);

	return 0;
} /* md__gc() */


static const luaL_Reg md_methods[] = {
	{ "update", &md_update },
	{ "final",  &md_final },
	{ NULL,     NULL },
};

static const luaL_Reg md_metatable[] = {
	{ "__gc", &md__gc },
	{ NULL,   NULL },
};

static const luaL_Reg md_globals[] = {
	{ "new",       &md_new },
	{ "interpose", &md_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_digest(lua_State *L) {
	initall(L);

	luaL_newlib(L, md_globals);

	return 1;
} /* luaopen__openssl_digest() */


/*
 * HMAC - openssl.hmac
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int hmac_new(lua_State *L) {
	const void *key;
	size_t len;
	const EVP_MD *type;
	HMAC_CTX *ctx;

	key = luaL_checklstring(L, 1, &len);
	type = md_optdigest(L, 2);

	ctx = prepudata(L, sizeof *ctx, HMAC_CLASS, NULL);

	HMAC_Init_ex(ctx, key, len, type, NULL);

	return 1;
} /* hmac_new() */


static int hmac_interpose(lua_State *L) {
	return interpose(L, HMAC_CLASS);
} /* hmac_interpose() */


static int hmac_update(lua_State *L) {
	HMAC_CTX *ctx = luaL_checkudata(L, 1, HMAC_CLASS);
	int i, top = lua_gettop(L);

	for (i = 2; i < top; i++) {
		const void *p;
		size_t n;

		p = luaL_checklstring(L, i, &n);
		HMAC_Update(ctx, p, n);
	}

	lua_pushboolean(L, 1);
	
	return 1;
} /* hmac_update() */


static int hmac_final(lua_State *L) {
	HMAC_CTX *ctx = luaL_checkudata(L, 1, HMAC_CLASS);
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned len;

	HMAC_Final(ctx, hmac, &len);

	lua_pushlstring(L, (char *)hmac, len);

	return 1;
} /* hmac_final() */


static int hmac__gc(lua_State *L) {
	HMAC_CTX *ctx = luaL_checkudata(L, 1, HMAC_CLASS);

	HMAC_CTX_cleanup(ctx);

	return 0;
} /* hmac__gc() */


static const luaL_Reg hmac_methods[] = {
	{ "update", &hmac_update },
	{ "final",  &hmac_final },
	{ NULL,     NULL },
};

static const luaL_Reg hmac_metatable[] = {
	{ "__gc", &hmac__gc },
	{ NULL,   NULL },
};

static const luaL_Reg hmac_globals[] = {
	{ "new",       &hmac_new },
	{ "interpose", &hmac_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_hmac(lua_State *L) {
	initall(L);

	luaL_newlib(L, hmac_globals);

	return 1;
} /* luaopen__openssl_hmac() */


/*
 * Cipher - openssl.cipher
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const EVP_CIPHER *cipher_checktype(lua_State *L, int index) {
	const char *name = luaL_checkstring(L, index);
	const EVP_CIPHER *type;

	if (!(type = EVP_get_cipherbyname(name)))
		luaL_argerror(L, index, lua_pushfstring(L, "%s: invalid cipher type", name));

	return type;
} /* cipher_checktype() */


static int cipher_new(lua_State *L) {
	const EVP_CIPHER *type;
	EVP_CIPHER_CTX *ctx;

	type = cipher_checktype(L, 1);

	ctx = prepudata(L, sizeof *ctx, CIPHER_CLASS, NULL);
	EVP_CIPHER_CTX_init(ctx);

	if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, -1))
		return throwssl(L, "cipher.new");

	return 1;
} /* cipher_new() */


static int cipher_interpose(lua_State *L) {
	return interpose(L, HMAC_CLASS);
} /* cipher_interpose() */


static int cipher_init(lua_State *L, _Bool encrypt) {
	EVP_CIPHER_CTX *ctx = luaL_checkudata(L, 1, CIPHER_CLASS);
	const void *key, *iv;
	size_t n, m;

	key = luaL_checklstring(L, 2, &n);
	m = (size_t)EVP_CIPHER_CTX_key_length(ctx);
	luaL_argcheck(L, 2, n == m, lua_pushfstring(L, "%u: invalid key length (should be %u)", (unsigned)n, (unsigned)m));

	iv = luaL_optlstring(L, 3, NULL, &n);
	m = (size_t)EVP_CIPHER_CTX_iv_length(ctx);
	luaL_argcheck(L, 3, n == m, lua_pushfstring(L, "%u: invalid IV length (should be %u)", (unsigned)n, (unsigned)m));

	if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt))
		goto sslerr;

	if (!lua_isnoneornil(L, 4)) {
		luaL_checktype(L, 4, LUA_TBOOLEAN);

		if (!EVP_CIPHER_CTX_set_padding(ctx, lua_toboolean(L, 4)))
			goto sslerr;
	}

	lua_settop(L, 1);

	return 1;
sslerr:
	return throwssl(L, (encrypt)? "cipher:encrypt" : "cipher:decrypt");
} /* cipher_init() */


static int cipher_encrypt(lua_State *L) {
	return cipher_init(L, 1);
} /* cipher_encrypt() */


static int cipher_decrypt(lua_State *L) {
	return cipher_init(L, 0);
} /* cipher_decrypt() */


static int cipher_update(lua_State *L) {
	EVP_CIPHER_CTX *ctx = luaL_checkudata(L, 1, CIPHER_CLASS);
	const unsigned char *p, *pe;
	luaL_Buffer B;
	size_t block, step, n;

	block = EVP_CIPHER_CTX_block_size(ctx);

	if (LUAL_BUFFERSIZE < block * 2)
		return luaL_error(L, "cipher:update: LUAL_BUFFERSIZE(%u) < 2 * EVP_CIPHER_CTX_block_size(%u)", (unsigned)LUAL_BUFFERSIZE, (unsigned)block);

	step = LUAL_BUFFERSIZE - block;

	p = (const unsigned char *)luaL_checklstring(L, 2, &n);
	pe = p + n;

	luaL_buffinit(L, &B);

	while (p < pe) {
		int in = (int)MIN((size_t)(pe - p), step), out;

		if (!EVP_CipherUpdate(ctx, (void *)luaL_prepbuffer(&B), &out, p, in))
			goto sslerr;

		p += in;
		luaL_addsize(&B, out);
	}

	luaL_pushresult(&B);

	return 1;
sslerr:
	lua_pushnil(L);
	pusherror(L, NULL);

	return 2;
} /* cipher_update() */


static int cipher_final(lua_State *L) {
	EVP_CIPHER_CTX *ctx = luaL_checkudata(L, 1, CIPHER_CLASS);
	luaL_Buffer B;
	size_t block;
	int out;

	block = EVP_CIPHER_CTX_block_size(ctx);

	if (LUAL_BUFFERSIZE < block)
		return luaL_error(L, "cipher:update: LUAL_BUFFERSIZE(%u) < EVP_CIPHER_CTX_block_size(%u)", (unsigned)LUAL_BUFFERSIZE, (unsigned)block);

	luaL_buffinit(L, &B);

	if (!EVP_CipherFinal(ctx, (void *)luaL_prepbuffer(&B), &out))
		goto sslerr;

	luaL_addsize(&B, out);
	luaL_pushresult(&B);

	return 1;
sslerr:
	lua_pushnil(L);
	pusherror(L, NULL);

	return 2;
} /* cipher_final() */


static int cipher__gc(lua_State *L) {
	EVP_CIPHER_CTX *ctx = luaL_checkudata(L, 1, CIPHER_CLASS);

	EVP_CIPHER_CTX_cleanup(ctx);

	return 0;
} /* cipher__gc() */


static const luaL_Reg cipher_methods[] = {
	{ "encrypt", &cipher_encrypt },
	{ "decrypt", &cipher_decrypt },
	{ "update",  &cipher_update },
	{ "final",   &cipher_final },
	{ NULL,      NULL },
};

static const luaL_Reg cipher_metatable[] = {
	{ "__gc", &cipher__gc },
	{ NULL,   NULL },
};

static const luaL_Reg cipher_globals[] = {
	{ "new",       &cipher_new },
	{ "interpose", &cipher_interpose },
	{ NULL,        NULL },
};

int luaopen__openssl_cipher(lua_State *L) {
	initall(L);

	luaL_newlib(L, cipher_globals);

	return 1;
} /* luaopen__openssl_cipher() */


static void initall(lua_State *L) {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	addclass(L, BIGNUM_CLASS, bn_methods, bn_metatable);
	addclass(L, PUBKEY_CLASS, pk_methods, pk_metatable);
	addclass(L, X509_NAME_CLASS, xn_methods, xn_metatable);
	addclass(L, X509_GENS_CLASS, gn_methods, gn_metatable);
	addclass(L, X509_CERT_CLASS, xc_methods, xc_metatable);
	addclass(L, X509_CSR_CLASS, xr_methods, xr_metatable);
	addclass(L, X509_CHAIN_CLASS, xl_methods, xl_metatable);
	addclass(L, X509_STORE_CLASS, xs_methods, xs_metatable);
	addclass(L, SSL_CTX_CLASS, sx_methods, sx_metatable);
	addclass(L, SSL_CLASS, ssl_methods, ssl_metatable);
	addclass(L, DIGEST_CLASS, md_methods, md_metatable);
	addclass(L, HMAC_CLASS, hmac_methods, hmac_metatable);
	addclass(L, CIPHER_CLASS, cipher_methods, cipher_metatable);
} /* initall() */


#endif /* L_OPENSSL_H */
