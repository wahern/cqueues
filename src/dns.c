/* ==========================================================================
 * dns.c - Lua Continuation Queues
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
#include <stddef.h>	/* offsetof */
#include <stdlib.h>	/* free(3) */
#include <string.h>	/* strerror(3) memset(3) */

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>	/* AF_INET AF_INET6 */

#include <arpa/inet.h>	/* INET_ADDSTRLEN INET6_ADDRSTRLEN inet_ntop(3) */

#include <lua.h>
#include <lauxlib.h>

#include "lib/dns.h"
#include "cqueues.h"

#define RR_ANY_CLASS   "DNS RR Any"
#define RR_A_CLASS     "DNS RR A"
#define RR_NS_CLASS    "DNS RR NS"
#define RR_CNAME_CLASS "DNS RR CNAME"
#define RR_SOA_CLASS   "DNS RR SOA"
#define RR_PTR_CLASS   "DNS RR PTR"
#define RR_MX_CLASS    "DNS RR MX"
#define RR_TXT_CLASS   "DNS RR TXT"
#define RR_AAAA_CLASS  "DNS RR AAAA"
#define RR_SRV_CLASS   "DNS RR SRV"
#define RR_OPT_CLASS   "DNS RR OPT"
#define RR_SSHFP_CLASS "DNS RR SSHFP"
#define RR_SPF_CLASS   "DNS RR SPF"

#define PACKET_CLASS   "DNS Packet"
#define RESCONF_CLASS  "DNS resolv.conf"
#define RESOLVER_CLASS "DNS Resolver"


static int optfint(lua_State *L, int t, const char *k, int def) {
	int i;

	lua_getfield(L, t, k);
	i = luaL_optint(L, -1, def);
	lua_pop(L, 1);

	return i;
} /* optfint() */


static void dnsL_loadall(lua_State *);


/*
 * R E S O U R C E  R E C O R D  B I N D I N G S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct rr {
	struct dns_rr attr;
	char *name;
	union dns_any data;
}; /* struct rr */


static const struct rr_info {
	const char *tname;
	unsigned short bufsiz;
} rrinfo[] = {
	[DNS_T_A]     = { RR_A_CLASS,     sizeof (struct dns_a) },
	[DNS_T_NS]    = { RR_NS_CLASS,    sizeof (struct dns_ns) },
	[DNS_T_CNAME] = { RR_CNAME_CLASS, sizeof (struct dns_cname) },
	[DNS_T_SOA]   = { RR_SOA_CLASS,   sizeof (struct dns_soa) },
	[DNS_T_PTR]   = { RR_PTR_CLASS,   sizeof (struct dns_ptr) },
	[DNS_T_MX]    = { RR_MX_CLASS,    sizeof (struct dns_mx) },
	[DNS_T_TXT]   = { RR_TXT_CLASS,   0 },
	[DNS_T_AAAA]  = { RR_AAAA_CLASS,  sizeof (struct dns_aaaa) },
	[DNS_T_SRV]   = { RR_SRV_CLASS,   sizeof (struct dns_srv) },
	[DNS_T_OPT]   = { RR_OPT_CLASS,   sizeof (struct dns_opt) },
	[DNS_T_SSHFP] = { RR_SSHFP_CLASS, sizeof (struct dns_sshfp) },
	[DNS_T_SPF]   = { RR_SPF_CLASS,   0 },
};

static const struct rr_info *rr_info(int type) {
	return (type >= 0 && type < (int)countof(rrinfo))? &rrinfo[type] : 0;
} /* rr_info() */

static const char *rr_tname(const struct dns_rr *rr) {
	const struct rr_info *info;

	if ((info = rr_info(rr->type)) && info->tname)
		return info->tname;
	else
		return RR_ANY_CLASS;
} /* rr_tname() */

static size_t rr_bufsiz(const struct dns_rr *rr) {
	const struct rr_info *info;
	size_t minbufsiz = offsetof(struct dns_txt, data) + rr->rd.len + 1;

	if ((info = rr_info(rr->type)) && info->bufsiz)
		return MAX(info->bufsiz, minbufsiz);
	else
		return minbufsiz;
} /* rr_bufsiz() */

static void rr_push(lua_State *L, struct dns_rr *any, struct dns_packet *P) {
	char name[DNS_D_MAXNAME + 1];
	size_t namelen, datasiz;
	struct rr *rr;
	int error;

	namelen = dns_d_expand(name, sizeof name, any->dn.p, P, &error);
	datasiz = rr_bufsiz(any);

	rr = lua_newuserdata(L, offsetof(struct rr, data) + datasiz + namelen + 1);

	rr->attr = *any;

	rr->name = (char *)rr + offsetof(struct rr, data) + datasiz;
	memcpy(rr->name, name, namelen);
	rr->name[namelen] = '\0';

	memset(&rr->data, '\0', datasiz);

	if (any->section != DNS_S_QD) {
		dns_any_init(&rr->data, datasiz);

		if ((error = dns_any_parse(&rr->data, any, P)))
			luaL_error(L, "dns.rr.parse: %s", dns_strerror(error));
	}

	luaL_setmetatable(L, rr_tname(any));
} /* rr_push() */


static struct rr *rr_toany(lua_State *L, int index) {
	luaL_checktype(L, index, LUA_TUSERDATA);
	luaL_argcheck(L, lua_rawlen(L, index) > offsetof(struct rr, data) + 4, index, "DNS RR userdata too small");

	return lua_touserdata(L, index);
} /* rr_toany() */


/*
 * ANY RR Bindings
 */
static int any_section(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	lua_pushinteger(L, rr->attr.section);

	return 1;
} /* any_section() */

static int any_name(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	lua_pushstring(L, rr->name);

	return 1;
} /* any_name() */

static int any_type(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	lua_pushinteger(L, rr->attr.type);

	return 1;
} /* any_type() */

static int any_class(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	lua_pushinteger(L, rr->attr.class);

	return 1;
} /* any_class() */

static int any_ttl(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	lua_pushinteger(L, rr->attr.ttl);

	return 1;
} /* any_ttl() */

static int any_rdata(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	if (rr->attr.section == DNS_S_QD)
		return lua_pushliteral(L, ""), 1;

	lua_pushlstring(L, (char *)rr->data.rdata.data, rr->data.rdata.len);

	return 1;
} /* any_rdata() */

static int any__tostring(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	if (rr->attr.section == DNS_S_QD)
		return lua_pushliteral(L, ""), 1;

	if (luaL_testudata(L, 1, RR_ANY_CLASS)) {
		lua_pushlstring(L, (char *)rr->data.rdata.data, rr->data.rdata.len);
	} else {
		luaL_Buffer B;
		size_t len;

		luaL_buffinit(L, &B);
		len = dns_any_print(luaL_prepbuffer(&B), LUAL_BUFFERSIZE, &rr->data, rr->attr.type);
		luaL_addsize(&B, len);
		luaL_pushresult(&B);
	}

	return 1;
} /* any__tostring() */

static const luaL_Reg any_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "rdata",   &any_rdata },
	{ NULL,      NULL }
}; /* any_methods[] */

static const luaL_Reg any_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* any_metatable[] */


/*
 * A RR Bindings
 */
static int a_addr(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_A_CLASS);
	char addr[INET_ADDRSTRLEN + 1] = "";

	if (rr->attr.section != DNS_S_QD)
		inet_ntop(AF_INET, &rr->data.a.addr, addr, sizeof addr);
	lua_pushstring(L, addr);

	return 1;
} /* a_addr() */

static const luaL_Reg a_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "addr",    &a_addr },
	{ NULL,      NULL }
}; /* a_methods[] */

static const luaL_Reg a_metatable[] = {
	{ "__tostring", &a_addr },
	{ NULL,         NULL }
}; /* a_metatable[] */


/*
 * NS, CNAME, PTR RR Bindings
 */
static int ns_host(lua_State *L) {
	struct rr *rr = rr_toany(L, 1);

	if (rr->attr.section == DNS_S_QD)
		return lua_pushliteral(L, ""), 1;

	lua_pushstring(L, rr->data.ns.host);

	return 1;
} /* ns_host() */

static const luaL_Reg ns_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "host",    &ns_host },
	{ NULL,      NULL }
}; /* ns_methods[] */

static const luaL_Reg ns_metatable[] = {
	{ "__tostring", &ns_host },
	{ NULL,         NULL }
}; /* ns_metatable[] */


/*
 * SOA RR Bindings
 */
static int soa_mname(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushstring(L, rr->data.soa.mname);

	return 1;
} /* soa_mname() */

static int soa_rname(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushstring(L, rr->data.soa.rname);

	return 1;
} /* soa_rname() */

static int soa_serial(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushinteger(L, rr->data.soa.serial);

	return 1;
} /* soa_serial() */

static int soa_refresh(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushinteger(L, rr->data.soa.refresh);

	return 1;
} /* soa_refresh() */

static int soa_retry(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushinteger(L, rr->data.soa.retry);

	return 1;
} /* soa_retry() */

static int soa_expire(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushinteger(L, rr->data.soa.expire);

	return 1;
} /* soa_expire() */

static int soa_minimum(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SOA_CLASS);

	lua_pushinteger(L, rr->data.soa.minimum);

	return 1;
} /* soa_minimum() */

static const luaL_Reg soa_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "mname",   &soa_mname },
	{ "rname",   &soa_rname },
	{ "serial",  &soa_serial },
	{ "refresh", &soa_refresh },
	{ "retry",   &soa_retry },
	{ "expire",  &soa_expire },
	{ "minimum", &soa_minimum },
	{ NULL,    NULL }
}; /* soa_methods[] */

static const luaL_Reg soa_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* soa_metatable[] */


/*
 * MX RR Bindings
 */
static int mx_host(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_MX_CLASS);

	lua_pushstring(L, rr->data.mx.host);

	return 1;
} /* mx_host() */

static int mx_preference(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_MX_CLASS);

	lua_pushinteger(L, rr->data.mx.preference);

	return 1;
} /* mx_preference() */

static const luaL_Reg mx_methods[] = {
	{ "section",    &any_section },
	{ "name",       &any_name },
	{ "type",       &any_type },
	{ "class",      &any_class },
	{ "ttl",        &any_ttl },
	{ "host",       &mx_host },
	{ "preference", &mx_preference },
	{ NULL,         NULL }
}; /* mx_methods[] */

static const luaL_Reg mx_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* mx_metatable[] */


/*
 * TXT RR Bindings
 */
static const luaL_Reg txt_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "data",    &any_rdata },
	{ NULL,      NULL }
}; /* txt_methods[] */

static const luaL_Reg txt_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* txt_metatable[] */


/*
 * AAAA RR Bindings
 */
static int aaaa_addr(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_AAAA_CLASS);
	char addr[INET6_ADDRSTRLEN + 1] = "";

	if (rr->attr.section != DNS_S_QD)
		inet_ntop(AF_INET6, &rr->data.aaaa.addr, addr, sizeof addr);
	lua_pushstring(L, addr);

	return 1;
} /* aaaa_addr() */

static const luaL_Reg aaaa_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "addr",    &aaaa_addr },
	{ NULL,      NULL }
}; /* aaaa_methods[] */

static const luaL_Reg aaaa_metatable[] = {
	{ "__tostring", &aaaa_addr },
	{ NULL,         NULL }
}; /* aaaa_metatable[] */


/*
 * SRV RR Bindings
 */
static int srv_priority(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SRV_CLASS);

	lua_pushinteger(L, rr->data.srv.priority);

	return 1;
} /* srv_priority() */

static int srv_weight(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SRV_CLASS);

	lua_pushinteger(L, rr->data.srv.weight);

	return 1;
} /* srv_weight() */

static int srv_port(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SRV_CLASS);

	lua_pushinteger(L, rr->data.srv.port);

	return 1;
} /* srv_port() */

static int srv_target(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SRV_CLASS);

	lua_pushstring(L, rr->data.srv.target);

	return 1;
} /* srv_target() */

static const luaL_Reg srv_methods[] = {
	{ "section",  &any_section },
	{ "name",     &any_name },
	{ "type",     &any_type },
	{ "class",    &any_class },
	{ "ttl",      &any_ttl },
	{ "priority", &srv_priority },
	{ "weight",   &srv_weight },
	{ "port",     &srv_port },
	{ "target",   &srv_target },
	{ NULL,       NULL }
}; /* srv_methods[] */

static const luaL_Reg srv_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* srv_metatable[] */


/*
 * OPT RR Bindings
 */
static int opt_rcode(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_OPT_CLASS);

	lua_pushinteger(L, rr->data.opt.rcode);

	return 1;
} /* opt_rcode() */

static int opt_version(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_OPT_CLASS);

	lua_pushinteger(L, rr->data.opt.version);

	return 1;
} /* opt_version() */

static int opt_maxsize(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_OPT_CLASS);

	lua_pushinteger(L, rr->data.opt.maxsize);

	return 1;
} /* opt_maxsize() */

static const luaL_Reg opt_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "rcode",   &opt_rcode },
	{ "version", &opt_version },
	{ "maxsize", &opt_maxsize },
	{ NULL,      NULL }
}; /* opt_methods[] */

static const luaL_Reg opt_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* opt_metatable[] */


/*
 * SSHFP RR Bindings
 */
static int sshfp_algo(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SSHFP_CLASS);

	lua_pushinteger(L, rr->data.sshfp.algo);

	return 1;
} /* sshfp_algo() */


static int sshfp_digest(lua_State *L) {
	struct rr *rr = luaL_checkudata(L, 1, RR_SSHFP_CLASS);
	int fmt = luaL_checkoption(L, 2, "x", (const char *[]){ "s", "x", 0 });
	unsigned char *hash;
	size_t hashlen;

	lua_pushinteger(L, rr->data.sshfp.type);

	switch (rr->data.sshfp.type) {
	case DNS_SSHFP_SHA1:
		hash = rr->data.sshfp.digest.sha1;
		hashlen = sizeof rr->data.sshfp.digest.sha1;

		break;
	default:
		lua_pushnil(L);

		return 2;
	}

	switch (fmt) {
	case 1: {
		luaL_Buffer B;
		size_t i;

		luaL_buffinit(L, &B);

		for (i = 0; i < hashlen; i++) {
			luaL_addchar(&B, "0123456789abcdef"[0x0f & (hash[i] >> 4)]);
			luaL_addchar(&B, "0123456789abcdef"[0x0f & (hash[i] >> 0)]);
		}

		luaL_pushresult(&B);

		break;
	}
	default:
		lua_pushlstring(L, (char *)hash, hashlen);
		break;
	} /* switch() */

	return 2;
} /* sshfp_digest() */


static const luaL_Reg sshfp_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "algo",    &sshfp_algo },
	{ "digest",  &sshfp_digest },
	{ NULL,     NULL }
}; /* sshfp_methods[] */

static const luaL_Reg sshfp_metatable[] = {
	{ "__tostring", &any__tostring },
	{ NULL,         NULL }
}; /* sshfp_metatable[] */


/*
 * SPF RR Bindings
 */
static const luaL_Reg spf_methods[] = {
	{ "section", &any_section },
	{ "name",    &any_name },
	{ "type",    &any_type },
	{ "class",   &any_class },
	{ "ttl",     &any_ttl },
	{ "policy",  &any_rdata },
	{ "data",    &any_rdata },
	{ NULL,      NULL }
}; /* spf_methods[] */

static const luaL_Reg spf_metatable[] = {
	{ "__tostring", &any_rdata },
	{ NULL,         NULL }
}; /* spf_metatable[] */


static void rr_loadall(lua_State *L) {
	cqs_addclass(L, RR_ANY_CLASS, any_methods, any_metatable);
	cqs_addclass(L, RR_A_CLASS, a_methods, a_metatable);
	cqs_addclass(L, RR_NS_CLASS, ns_methods, ns_metatable);
	cqs_addclass(L, RR_CNAME_CLASS, ns_methods, ns_metatable);
	cqs_addclass(L, RR_SOA_CLASS, soa_methods, soa_metatable);
	cqs_addclass(L, RR_PTR_CLASS, ns_methods, ns_metatable);
	cqs_addclass(L, RR_MX_CLASS, mx_methods, mx_metatable);
	cqs_addclass(L, RR_TXT_CLASS, txt_methods, txt_metatable);
	cqs_addclass(L, RR_AAAA_CLASS, aaaa_methods, aaaa_metatable);
	cqs_addclass(L, RR_SRV_CLASS, srv_methods, srv_metatable);
	cqs_addclass(L, RR_OPT_CLASS, opt_methods, opt_metatable);
	cqs_addclass(L, RR_SSHFP_CLASS, sshfp_methods, sshfp_metatable);
	cqs_addclass(L, RR_SPF_CLASS, spf_methods, spf_metatable);
} /* rr_loadall() */


/*
 * P A C K E T  B I N D I N G S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int pkt_new(lua_State *L) {
	struct dns_packet *P;
	size_t size;

	size = luaL_optunsigned(L, 1, DNS_P_QBUFSIZ);
	P = memset(lua_newuserdata(L, size), '\0', size);
	luaL_setmetatable(L, PACKET_CLASS);

	dns_p_init(P, size);

	return 1;
} /* pkt_new() */


static int pkt_qid(lua_State *L) {
	struct dns_packet *P = lua_touserdata(L, 1);

	lua_pushinteger(L, ntohs(dns_header(P)->qid));

	return 1;
} /* pkt_qid() */


static int pkt_flags(lua_State *L) {
	struct dns_packet *P = lua_touserdata(L, 1);
	struct dns_header *hdr = dns_header(P);

	lua_newtable(L);

	lua_pushboolean(L, hdr->qr);
	lua_setfield(L, -2, "qr");

	lua_pushinteger(L, hdr->opcode);
	lua_setfield(L, -2, "opcode");

	lua_pushboolean(L, hdr->aa);
	lua_setfield(L, -2, "aa");

	lua_pushboolean(L, hdr->tc);
	lua_setfield(L, -2, "tc");

	lua_pushboolean(L, hdr->rd);
	lua_setfield(L, -2, "rd");

	lua_pushboolean(L, hdr->ra);
	lua_setfield(L, -2, "ra");

	lua_pushinteger(L, hdr->unused);
	lua_setfield(L, -2, "z");

	lua_pushinteger(L, hdr->rcode);
	lua_setfield(L, -2, "rcode");

	return 1;
} /* pkt_flags() */


static int pkt_count(lua_State *L) {
	struct dns_packet *P = lua_touserdata(L, 1);
	int flags = luaL_optinteger(L, 2, DNS_S_ALL);

	lua_pushinteger(L, dns_p_count(P, flags));

	return 1;
} /* pkt_count() */


static int pkt__next(lua_State *L) {
	struct dns_packet *P = lua_touserdata(L, lua_upvalueindex(1));
	struct dns_rr_i *rr_i = lua_touserdata(L, lua_upvalueindex(2));
	struct dns_rr rr;
	int error = 0;

	if (!dns_rr_grep(&rr, 1, rr_i, P, &error))
		return (error)? luaL_error(L, "dns.packet:grep: %s", dns_strerror(error)) : 0;

	rr_push(L, &rr, P);

	return 1;
} /* pkt__next() */

static int pkt_grep(lua_State *L) {
	struct dns_packet *P = luaL_checkudata(L, 1, PACKET_CLASS);
	struct dns_rr_i *rr_i;

	lua_settop(L, 2);

	lua_pushvalue(L, 1);
	rr_i = memset(lua_newuserdata(L, sizeof *rr_i), '\0', sizeof *rr_i);
	rr_i = dns_rr_i_init(rr_i, P);

	if (!lua_isnil(L, 2)) {
		luaL_checktype(L, 2, LUA_TTABLE);

		rr_i->section = optfint(L, -1, "section", 0);
		rr_i->type = optfint(L, -1, "type", 0);
		rr_i->class = optfint(L, -1, "class", 0);

		lua_getfield(L, -1, "name");
		if (!(rr_i->name = luaL_optstring(L, -1, NULL)))
			lua_pop(L, 1);
	}

	lua_pushcclosure(L, &pkt__next, lua_gettop(L) - 2);

	return 1;
} /* pkt_grep() */


static const luaL_Reg pkt_methods[] = {
	{ "qid",    &pkt_qid },
	{ "flags",  &pkt_flags },
	{ "count",  &pkt_count },
	{ "grep",   &pkt_grep },
	{ NULL,     NULL },
}; /* pkt_methods[] */

static const luaL_Reg pkt_metatable[] = {
	{ NULL, NULL }
}; /* pkt_metatable[] */

static const luaL_Reg pkt_globals[] = {
	{ "new", &pkt_new },
	{ NULL,  NULL }
};

int luaopen__cqueues_dns_packet(lua_State *L) {
	static const struct { const char *name; int value; } macro[] = {
		{ "QUESTION", DNS_S_QD }, { "ANSWER", DNS_S_AN },
		{ "AUTHORITY", DNS_S_NS }, { "ADDITIONAL", DNS_S_AR },

		{ "QUERY", DNS_OP_QUERY }, { "IQUERY", DNS_OP_IQUERY },
		{ "STATUS", DNS_OP_STATUS }, { "NOTIFY", DNS_OP_NOTIFY },
		{ "UPDATE", DNS_OP_UPDATE },

		{ "NOERROR", DNS_RC_NOERROR }, { "FORMERR", DNS_RC_FORMERR },
		{ "SERVFAIL", DNS_RC_SERVFAIL }, { "NXDOMAIN", DNS_RC_NXDOMAIN },
		{ "NOTIMP", DNS_RC_NOTIMP }, { "REFUSED", DNS_RC_REFUSED },
		{ "YXDOMAIN", DNS_RC_YXDOMAIN }, { "YXRRSET", DNS_RC_YXRRSET },
		{ "NXRRSET", DNS_RC_NXRRSET }, { "NOTAUTH", DNS_RC_NOTAUTH },
		{ "NOTZONE", DNS_RC_NOTZONE },
	};
	unsigned i;

	dnsL_loadall(L);

	luaL_newlib(L, pkt_globals);

	for (i = 0; i < countof(macro); i++) {
		lua_pushinteger(L, macro[i].value);
		lua_pushstring(L, macro[i].name);
		lua_rawset(L, -2);
	}

	return 1;
} /* luaopen__cqueues_dns_packet() */


/*
 * R E S O L V . C O N F  B I N D I N G S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int resconf_new(lua_State *L) {
	return 0;
} /* resconf_new() */


static const luaL_Reg resconf_methods[] = {
	{ NULL,     NULL },
}; /* resconf_methods[] */

static const luaL_Reg resconf_metatable[] = {
	{ NULL, NULL }
}; /* resconf_metatable[] */

static const luaL_Reg resconf_globals[] = {
	{ "new", &resconf_new },
	{ NULL,  NULL }
};

int luaopen__cqueues_dns_resolv_conf(lua_State *L) {
	dnsL_loadall(L);

	luaL_newlib(L, resconf_globals);

	lua_pushinteger(L, DNS_RESCONF_TCP_ENABLE);
	lua_setfield(L, -2, "TCP_ENABLE");

	lua_pushinteger(L, DNS_RESCONF_TCP_ONLY);
	lua_setfield(L, -2, "TCP_ONLY");

	lua_pushinteger(L, DNS_RESCONF_TCP_DISABLE);
	lua_setfield(L, -2, "TCP_DISABLE");

	return 1;
} /* luaopen__cqueues_dns_resolv_conf() */


/*
 * R E S O L V E R  B I N D I N G S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int res_new(lua_State *L) {
	return 0;
} /* res_new() */


static int res_interpose(lua_State *L) {
	return cqs_interpose(L, RESOLVER_CLASS);
} /* res_interpose() */


static int res_stub(lua_State *L) {
	struct dns_resolver **R = lua_newuserdata(L, sizeof *R);
	int error;

	*R = 0;
	luaL_setmetatable(L, RESOLVER_CLASS);

	if ((*R = dns_res_stub(dns_opts(), &error)))
		return 1;

	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* res_stub() */


static inline struct dns_resolver *res_check(lua_State *L, int index) {
	return *(struct dns_resolver **)luaL_checkudata(L, index, RESOLVER_CLASS);
} /* res_check() */


static int res_submit(lua_State *L) {
	struct dns_resolver *R = res_check(L, 1);
	const char *name = luaL_checkstring(L, 2);
	int type = luaL_optint(L, 3, DNS_T_A);
	int class = luaL_optint(L, 4, DNS_C_IN);
	int error;

	if (!(error = dns_res_submit(R, name, type, class))) {
		lua_pushboolean(L, 1);

		return 1;
	} else {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}
} /* res_submit() */


static int res_fetch(lua_State *L) {
	struct dns_resolver *R = res_check(L, 1);
	struct dns_packet *pkt;
	size_t size;
	int error;

	if ((error = dns_res_check(R)) || !(pkt = dns_res_fetch(R, &error))) {
error:
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}

	size = dns_p_sizeof(pkt);
	error = dns_p_study(dns_p_copy(dns_p_init(lua_newuserdata(L, size), size), pkt));
	free(pkt);

	if (error)
		goto error;

	luaL_setmetatable(L, PACKET_CLASS);

	return 1;
} /* res_fetch() */


static int res_pollfd(lua_State *L) {
	struct dns_resolver *R = res_check(L, 1);

	lua_pushinteger(L, dns_res_pollfd(R));

	return 1;
} /* res_pollfd() */


static int res_events(lua_State *L) {
	struct dns_resolver *R = res_check(L, 1);

	switch (dns_res_events(R)) {
	case POLLIN|POLLOUT:
		lua_pushliteral(L, "rw");
		break;
	case POLLIN:
		lua_pushliteral(L, "r");
		break;
	case POLLOUT:
		lua_pushliteral(L, "w");
		break;
	default:
		lua_pushnil(L);
		break;
	}

	return 1;
} /* res_events() */


static const luaL_Reg res_methods[] = {
	{ "submit",  &res_submit },
	{ "fetch",   &res_fetch },
	{ "pollfd",  &res_pollfd },
	{ "events",  &res_events },
	{ NULL,     NULL },
}; /* res_methods[] */

static const luaL_Reg res_metatable[] = {
	{ NULL, NULL }
}; /* res_metatable[] */

static const luaL_Reg res_globals[] = {
	{ "new",       &res_new },
	{ "interpose", &res_interpose },
	{ "stub",      &res_stub },
	{ NULL,        NULL }
};

int luaopen__cqueues_dns_resolver(lua_State *L) {
	dnsL_loadall(L);

	luaL_newlib(L, res_globals);

	return 1;
} /* luaopen__cqueues_dns_resolver() */


/*
 * G L O B A L  B I N D I N G S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int dnsL_version(lua_State *L) {
	lua_pushinteger(L, dns_v_rel());
	lua_pushinteger(L, dns_v_abi());
	lua_pushinteger(L, dns_v_api());

	return 3;
} /* dnsL_version() */

static const luaL_Reg dnsL_globals[] = {
	{ "version", &dnsL_version },
	{ NULL,      NULL }
};

int luaopen__cqueues_dns(lua_State *L) {
	luaL_newlib(L, dnsL_globals);

	dnsL_loadall(L);

	return 1;
} /* luaopen__cqueues_dns() */


static void dnsL_loadall(lua_State *L) {
	rr_loadall(L);
	cqs_addclass(L, PACKET_CLASS, pkt_methods, pkt_metatable);
	cqs_addclass(L, RESOLVER_CLASS, res_methods, res_metatable);
} /* dnsL_loadall() */