/* ==========================================================================
 * socket.c - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012, 2013, 2014  William Ahern
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

#include <stddef.h>	/* NULL offsetof size_t */
#include <stdarg.h>	/* va_list va_start va_arg va_end */
#include <stdlib.h>	/* strtol(3) */
#include <string.h>	/* memset(3) memchr(3) memcpy(3) memmem(3) */
#include <math.h>	/* NAN */
#include <errno.h>	/* EBADF ENOTSOCK EOPNOTSUPP EOVERFLOW EPIPE */

#include <sys/types.h>
#include <sys/socket.h>	/* AF_UNIX MSG_CMSG_CLOEXEC SOCK_CLOEXEC SOCK_STREAM SOCK_SEQPACKET SOCK_DGRAM PF_UNSPEC socketpair(2) */
#include <sys/un.h>	/* struct sockaddr_un */
#include <unistd.h>	/* dup(2) */
#include <fcntl.h>      /* F_DUPFD_CLOEXEC fcntl(2) */
#include <arpa/inet.h>	/* ntohs(3) */

#include <openssl/ssl.h> /* SSL_CTX, SSL_CTX_free(), SSL_CTX_up_ref(), SSL, SSL_up_ref() */
#include <openssl/crypto.h> /* CRYPTO_LOCK_SSL CRYPTO_add() */

#include <lua.h>
#include <lauxlib.h>

#include "lib/socket.h"
#include "lib/fifo.h"
#include "lib/dns.h"

#include "cqueues.h"


/*
 * F E A T U R E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define HAVE_OPENSSL11_API (!(OPENSSL_VERSION_NUMBER < 0x10100001L || defined LIBRESSL_VERSION_NUMBER))

#ifndef HAVE_SSL_CTX_UP_REF
#define HAVE_SSL_CTX_UP_REF HAVE_OPENSSL11_API
#endif

#ifndef HAVE_SSL_UP_REF
#define HAVE_SSL_UP_REF HAVE_OPENSSL11_API
#endif


/*
 * C O M P A T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !HAVE_SSL_CTX_UP_REF
#define SSL_CTX_up_ref(ctx) CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)
#endif

#if !HAVE_SSL_UP_REF
#define SSL_up_ref(ssl) CRYPTO_add(&(ssl)->references, 1, CRYPTO_LOCK_SSL)
#endif


/*
 * T E X T  M U N G I N G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static inline _Bool mime_isblank(unsigned char ch) {
	return ch == 32 || ch == 9;
} /* mime_isblank() */


static inline _Bool mime_isfname(unsigned char ch) {
	return ch >= 33 && ch <= 126 && ch != 58 /* : */;
} /* mime_isfname() */


static int iov_chr(const struct iovec *iov, size_t p) {
	return (p < iov->iov_len)? ((unsigned char *)iov->iov_base)[p] : -1;
} /* iov_chr() */


static int iov_lc(const struct iovec *iov) {
	return (iov->iov_len)? iov_chr(iov, iov->iov_len - 1) : -1;
} /* iov_lc() */


static int iov_addzu(size_t *r, size_t a, size_t b) {
	int error;

	if ((error = cqs_addzu(r, a, b)))
		return error;

	return (*r == (size_t)-1)? EOVERFLOW : 0;
} /* iov_addzu() */


/*
 * Find end of MIME header. Returns 0 < length <= .iov_len to end of header,
 * 0 if not found. If length is >.iov_len then needs more data. Returns -1
 * on error.
 */
#define IOV_F_EMPTYFNAME 1

static size_t iov_eoh(const struct iovec *iov, _Bool eof, int flags, int *_error) {
	const char *tp, *p, *pe;
	size_t n;
	int error;

	tp = iov->iov_base;
	p = tp;
	pe = tp + iov->iov_len;

	while (p < pe && mime_isfname(*p))
		p++;

	if (p == tp && p < pe && !(flags & IOV_F_EMPTYFNAME))
		return 0; /* not allowing empty field names */

	while (p < pe && mime_isblank(*p))
		p++;

	if (p < pe && *p != ':')
		return 0; /* not a valid field name */

	while (p < pe && (p = memchr(p, '\n', pe - p))) {
		if (++p < pe && !mime_isblank(*p))
			return p - tp; /* found */
	}

	if (eof)
		return 0; /* do not allow truncated headers */

	if ((error = iov_addzu(&n, iov->iov_len, 1)))
		goto error;

	return n; /* need more */
error:
	*_error = error;

	return -1;
} /* iov_eoh() */


/*
 * Find end of MIME boundary marker. Returns length to end of marker, or 0
 * if not found.
 */
static size_t iov_eob(const struct iovec *iov, const char *eob, size_t eoblen) {
	const char *p;

	if (iov->iov_len < eoblen)
		return 0;

	if ((p = memmem(iov->iov_base, iov->iov_len, eob, eoblen)))
		return (p + eoblen) - (char *)iov->iov_base;

	return 0;
} /* iov_eob() */


/*
 * Find end of text region which would fill >= minbuf and <= maxbuf after
 * calling iov_trimcr, and without leaving a trailing \r unless EOF. If
 * return value > iov.iov_len, then need more data. Returns -1 on error.
 */
static size_t iov_eot(const struct iovec *iov, size_t minbuf, size_t maxbuf, _Bool eof, int *_error) {
	const char *p, *pe;
	size_t n = 0, eot;
	int lc = -1, error;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	for (; p < pe && n < maxbuf; ++n) {
		lc = *p++;

		if (lc == '\r' && p < pe && *p == '\n') {
			lc = *p++; /* skip \n so we don't ++n */
		}
	}

	if ((size_t)-1 == (eot = p - (char *)iov->iov_base)) {
		error = EOVERFLOW;
		goto error;
	}

	if (n < maxbuf) {
		if (!eof) {
			if (n >= minbuf && lc != '\r') {
				/*
				 * just continue as we're not splitting a
				 * \r\n pair
				 */
				(void)0;
			} else if (n > minbuf && lc == '\r') {
				/*
				 * just exclude it. we might end up
				 * returning a trailing \r, but we know for
				 * a fact it's not part of a \r\n pair.
				 */
				--eot;
			} else if ((error = iov_addzu(&eot, eot, maxbuf - n))) {
				goto error;
			}
		}
	} else if (lc == '\r') {
		if (n > minbuf) {
			--eot; /* see comment ~10 lines above */
		} else if ((error = iov_addzu(&eot, eot, 1))) {
			goto error;
		}
	}

	return eot;
error:
	*_error = error;

	return -1;
} /* iov_eot() */


static size_t iov_eol(const struct iovec *iov) {
	const char *p, *pe;
	size_t eol = 0;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	while (p < pe && (p = memchr(p, '\n', pe - p))) {
		eol = ++p - (char *)iov->iov_base;
	}

	return (eol)? eol : iov->iov_len;
} /* iov_eol() */


/* strip \r from \r\n sequences */
static size_t iov_trimcr(struct iovec *iov, _Bool chomp) {
	char *p, *pe;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	if (chomp) {
		if (pe - p >= 2 && pe[-1] == '\n' && pe[-2] == '\r')
			*(--pe - 1) = '\n';
	} else {
		while (p < pe && (p = memchr(p, '\r', pe - p))) {
			if (++p >= pe) {
				break;
			} else if (*p == '\n') {
				memmove(p - 1, p, pe - p);
				--pe;
			}
		}
	}

	return iov->iov_len = pe - (char *)iov->iov_base;
} /* iov_trimcr() */


/* strip \r?\n from \r?\n sequences */
static size_t iov_trimcrlf(struct iovec *iov, _Bool chomp) {
	char *sp, *p, *pe;

	sp = iov->iov_base;
	p = iov->iov_base;
	pe = p + iov->iov_len;

	if (chomp) {
		if (p < pe && pe[-1] == '\n') {
			--pe;

			if (p < pe && pe[-1] == '\r')
				--pe;
		}
	} else {
		while (p < pe && (p = memchr(p, '\n', pe - p))) {
			if (p > sp && p[-1] == '\r') {
				++p;
				memmove(p - 2, p, pe - p);
				pe -= 2;
			} else {
				memmove(p, p + 1, pe - p - 1);
				--pe;
			}
		}
	}

	return iov->iov_len = pe - (char *)iov->iov_base;
} /* iov_trimcrlf() */


/*
 * L U A  S O C K E T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define lso_error_t int
#define lso_nargs_t int

#define LSO_CLASS    "CQS Socket"
#define LSO_INDEX    1
#define LSO_UPVALUES 1

#define LSO_MAXERRS 100

#define LSO_BUFSIZ  4096
#define LSO_MAXLINE 4096
#define LSO_INFSIZ  ((size_t)-1)

#define LSO_LINEBUF   0x01
#define LSO_FULLBUF   0x02
#define LSO_NOBUF     0x04
#define LSO_ALLBUF    (LSO_LINEBUF|LSO_FULLBUF|LSO_NOBUF)
#define LSO_TEXT      0x08
#define LSO_BINARY    0x10
#define LSO_AUTOFLUSH 0x20
#define LSO_PUSHBACK  0x40

#define LSO_INITMODE  (LSO_LINEBUF|LSO_TEXT|LSO_AUTOFLUSH|LSO_PUSHBACK)
#define LSO_RDMASK    (~(LSO_ALLBUF|LSO_AUTOFLUSH))
#define LSO_WRMASK    (~LSO_PUSHBACK)

/*
 * A placeholder until we make it optional. Some Microsoft services have
 * buggy line buffering and will choke if, e.g., an SMTP command is
 * fragmented across TCP packets.
 */
#define LSO_DEFRAG 1

#if !defined __NetBSD__ || NETBSD_PREREQ(6,0)
#define LSO_NAN (NAN)
#else
#define LSO_NAN (__builtin_nan(""))
#endif

#define LSO_DO_FLUSH    0x01 /* flush output buffer */
#define LSO_DO_STARTTLS 0x02 /* initiate starttls */

struct luasocket {
	int todo, done;

	struct {
		_Bool once;
		struct so_starttls config;
	} tls;

	struct {
		int mode;
		size_t maxline;
		size_t bufsiz;

		struct fifo fifo;

		_Bool eof;
		_Bool eom;

		int error;
		size_t numerrs;
		size_t maxerrs;
	} ibuf;

	struct {
		int mode;
		size_t maxline;
		size_t bufsiz;

		struct fifo fifo;

		_Bool eof;
		size_t eol;

		int error;
		size_t numerrs;
		size_t maxerrs;
	} obuf;

	int type;
	struct socket *socket;

	cqs_ref_t onerror;

	lua_State *mainthread;

	double timeout;
}; /* struct luasocket */


static struct luasocket lso_initializer = {
	.ibuf = { .mode = (LSO_RDMASK & LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ, .maxerrs = LSO_MAXERRS },
	.obuf = { .mode = (LSO_WRMASK & LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ, .maxerrs = LSO_MAXERRS },
	.type = SOCK_STREAM,
	.onerror = LUA_NOREF,
	.timeout = LSO_NAN,
};


static size_t lso_optsize(struct lua_State *L, int index, size_t def) {
	lua_Number size;

	if (lua_isnoneornil(L, index))
		return def;

	size = luaL_checknumber(L, index);

	if (size < 0 || isinf(size))
		return LSO_INFSIZ;

	return (size > 0)? (size_t)size : def;
} /* lso_optsize() */


static size_t lso_checksize(struct lua_State *L, int index) {
	lua_Number size = luaL_checknumber(L, index);

	if (size < 0 || isinf(size))
		return LSO_INFSIZ;

	return (size_t)size;
} /* lso_checksize() */


static void lso_pushsize(struct lua_State *L, size_t size) {
	if (size == LSO_INFSIZ) {
		lua_pushnumber(L, INFINITY);
	} else {
		lua_pushinteger(L, size);
	}
} /* lso_pushsize() */


static int lso_tofileno(lua_State *L, int index) {
	struct luasocket *so;
	luaL_Stream *fh;

	if (lua_isnumber(L, index)) {
		return lua_tointeger(L, index);
	} else if ((so = luaL_testudata(L, index, LSO_CLASS))) {
		return so_peerfd(so->socket);
	} else if ((fh = luaL_testudata(L, index, LUA_FILEHANDLE))) {
		return (fh->f)? fileno(fh->f) : -1;
	} else {
		return -1;
	}
} /* lso_tofileno() */


static _Bool lso_getfield(lua_State *L, int index, const char *k) {
	lua_getfield(L, index, k);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		return 0;
	} else {
		return 1;
	}
} /* lso_getfield() */


static _Bool lso_rawgeti(lua_State *L, int index, int k) {
	lua_rawgeti(L, index, k);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		return 0;
	} else {
		return 1;
	}
} /* lso_rawgeti() */


static _Bool lso_altfield(lua_State *L, int index, ...) {
	const char *k;
	va_list ap;

	va_start(ap, index);

	while ((k = va_arg(ap, const char *))) {
		if (lso_getfield(L, index, k))
			break;
	}

	va_end(ap);

	return !!k;
} /* lso_altfield() */

#define lso_altfield(...) lso_altfield(__VA_ARGS__, (const char *)0)


static _Bool lso_popbool(lua_State *L) {
	_Bool val;
	luaL_checktype(L, -1, LUA_TBOOLEAN);
	val = lua_toboolean(L, -1);
	lua_pop(L, 1);
	return val;
} /* lso_popbool() */


static void *lso_singleton(lua_State *L, const void *key, const void *init, size_t len) {
	void *p;

	lua_rawgetp(L, LUA_REGISTRYINDEX, key);
	p = lua_touserdata(L, -1);
	lua_pop(L, 1);

	if (p)
		return p;

	p = lua_newuserdata(L, len);
	if (init)
		memcpy(p, init, len);
	else
		memset(p, 0, len);
	lua_rawsetp(L, LUA_REGISTRYINDEX, key);

	return p;
} /* lso_singleton() */


static mode_t lso_checkperm(lua_State *L, int index) {
	const char *mode = luaL_checkstring(L, index);
	mode_t perm = 0;

	if (*mode >= '0' && *mode <= '9') {
		perm = strtol(mode, NULL, 0);
	} else {
		int i = 9, flag, ch;

		while ((ch = *mode++) && i > 0) {
			if (ch == 'r' || ch == 'R')
				flag = 04;
			else if (ch == 'w' || ch == 'W')
				flag = 02;
			else if (ch == 'x' || ch == 'X')
				flag = 01;
			else if (ch == '-')
				flag = 00;
			else
				continue;

			perm |= (flag << (3 * (--i / 3)));
		}
	}

	return perm;
} /* lso_checkperm() */


static struct so_options lso_checkopts(lua_State *L, int index) {
	struct so_options opts = *so_opts();

	/* TODO: Support explicit interface name via .if_name/.name */
	if (lso_altfield(L, index, "bind", "sa_bind")) {
		static const int regindex;
		struct sockaddr_storage *ss = lso_singleton(L, &regindex, NULL, sizeof *ss);
		const char *addr = NULL;
		int port = -1, error;

		if (lua_istable(L, -1)) {
			if (lso_altfield(L, -1, "addr", "address", "sin_addr", "sin6_addr") || lso_rawgeti(L, -1, 1)) {
				addr = luaL_checkstring(L, -1);
				lua_pop(L, 1);
			}

			if (lso_altfield(L, -1, "port", "sin_port", "sin6_port") || lso_rawgeti(L, -1, 2)) {
				port = luaL_checkint(L, -1);
				lua_pop(L, 1);
			}

		} else {
			addr = luaL_checkstring(L, -1);
		}

		luaL_argcheck(L, addr != NULL, index, "no bind address specified");

		if (!sa_pton(ss, sizeof *ss, addr, NULL, &error))
			luaL_argerror(L, index, lua_pushfstring(L, "%s: unable to parse bind address (%s)", addr, cqs_strerror(error)));

		if (port >= 0)
			*sa_port(ss, &(unsigned short){ 0 }, NULL) = htons((unsigned short)port);

		opts.sa_bind = ss;

		lua_pop(L, 1);
	}

	if (lso_altfield(L, index, "mode", "sun_mode")) {
		opts.sun_mode = S_IFSOCK | lso_checkperm(L, -1);
		lua_pop(L, 1);
	}

	if (lso_altfield(L, index, "mask", "sun_mask")) {
		opts.sun_mask = S_IFSOCK | lso_checkperm(L, -1);
		lua_pop(L, 1);
	}

	if (lso_altfield(L, index, "unlink", "sun_unlink"))
		opts.sun_unlink = lso_popbool(L);

	if (lso_altfield(L, index, "reuseaddr", "sin_reuseaddr"))
		opts.sin_reuseaddr = lso_popbool(L);

	if (lso_altfield(L, index, "reuseport", "sin_reuseport"))
		opts.sin_reuseport = lso_popbool(L);

	if (lso_altfield(L, index, "broadcast", "sin_broadcast"))
		opts.sin_broadcast = lso_popbool(L);

	if (lso_altfield(L, index, "nodelay", "sin_nodelay"))
		opts.sin_nodelay = lso_popbool(L);

	if (lso_altfield(L, index, "nopush", "sin_nopush"))
		opts.sin_nopush = lso_popbool(L);

	if (lso_altfield(L, index, "v6only", "sin_v6only"))
		opts.sin_v6only = (lso_popbool(L))? SO_V6ONLY_ENABLE : SO_V6ONLY_DISABLE;

	if (lso_altfield(L, index, "oobinline", "sin_oobinline"))
		opts.sin_oobinline = lso_popbool(L);

	if (lso_altfield(L, index, "nonblock", "fd_nonblock"))
		opts.fd_nonblock = lso_popbool(L);

	if (lso_altfield(L, index, "cloexec", "fd_cloexec"))
		opts.fd_cloexec = lso_popbool(L);

	if (lso_altfield(L, index, "nosigpipe", "fd_nosigpipe"))
		opts.fd_nosigpipe = lso_popbool(L);

	if (lso_altfield(L, index, "verify", "tls_verify"))
		opts.tls_verify = lso_popbool(L);

	if (lso_altfield(L, index, "sendname", "tls_sendname")) {
		if (lua_isboolean(L, -1)) {
			opts.tls_sendname = (lua_toboolean(L, -1))? SO_OPTS_TLS_HOSTNAME : NULL;
		} else {
			opts.tls_sendname = luaL_checkstring(L, -1);
		}

		lua_pop(L, 1);
	}

	if (lso_altfield(L, index, "time", "st_time"))
		opts.st_time = lso_popbool(L);

	return opts;
} /* lso_checkopts() */


static int lso_closefd(int *fd, void *arg) {
	struct luasocket *S = arg;

	if (S->mainthread) {
		cqs_cancelfd(S->mainthread, *fd);
		cqs_closefd(fd);
	}

	return 0;
} /* lso_closefd() */


static struct luasocket *lso_testself(lua_State *L, int index) {
	return cqs_testudata(L, index, LSO_INDEX);
} /* lso_testself() */


static struct luasocket *lso_checkvalid(lua_State *L, int index, struct luasocket *S) {
	luaL_argcheck(L, !!S->socket, index, "socket closed");
	return S;
} /* lso_checkvalid() */


static struct luasocket *lso_checkself(lua_State *L, int index) {
	return lso_checkvalid(L, index, cqs_checkudata(L, index, LSO_INDEX, LSO_CLASS));
} /* lso_checkself() */


static int lso_imode(const char *str, int init) {
	int mode = init, ch;

	while ((ch = *str++)) {
		switch (ch) {
		case 'n':
			mode = LSO_NOBUF | (mode & ~LSO_ALLBUF);
			break;
		case 'l':
			mode = LSO_LINEBUF | (mode & ~LSO_ALLBUF);
			break;
		case 'f':
			mode = LSO_FULLBUF | (mode & ~LSO_ALLBUF);
			break;
		case 't':
			mode = LSO_TEXT | (mode & ~LSO_BINARY);
			break;
		case 'b':
			mode = LSO_BINARY | (mode & ~LSO_TEXT);
			break;
		case 'a':
			mode |= LSO_AUTOFLUSH;
			break;
		case 'A':
			mode &= ~LSO_AUTOFLUSH;
			break;
		case 'p':
			mode |= LSO_PUSHBACK;
			break;
		case 'P':
			mode &= ~LSO_PUSHBACK;
			break;
		} /* switch() */
	} /* while() */

	return mode;
} /* lso_imode() */


static void lso_pushmode(lua_State *L, int mode, int mask, _Bool libc) {
	if (libc) {
		if (mode & LSO_NOBUF)
			lua_pushstring(L, "no");
		else if (mode & LSO_LINEBUF)
			lua_pushstring(L, "line");
		else if (mode & LSO_FULLBUF)
			lua_pushstring(L, "full");
		else
			lua_pushnil(L); /* XXX: shouldn't happen */
	} else {
		char flag[8], *p = flag;

		if (mode & LSO_TEXT)
			*p++ = 't';
		else if (mode & LSO_BINARY)
			*p++ = 'b';
		else
			*p++ = '-';

		if (mode & LSO_NOBUF)
			*p++ = 'n';
		else if (mode & LSO_LINEBUF)
			*p++ = 'l';
		else if (mode & LSO_FULLBUF)
			*p++ = 'f';
		else
			*p++ = '-';

		if (mask & LSO_AUTOFLUSH)
			*p++ = (mode & LSO_AUTOFLUSH)? 'a' : 'A';

		if (mask & LSO_PUSHBACK)
			*p++ = (mode & LSO_PUSHBACK)? 'p' : 'P';

		lua_pushlstring(L, flag, p - flag);
	}
} /* lso_pushmode() */


//static lso_nargs_t lso_throw(lua_State *L, struct luasocket *S, int error) {
//	return luaL_error(L, "socket: %s", cqs_strerror(error));
//} /* lso_throw() */


static struct luasocket *lso_prototype(lua_State *L) {
	static const int regindex;

	return lso_singleton(L, &regindex, &lso_initializer, sizeof lso_initializer);
} /* lso_prototype() */


static struct luasocket *lso_newsocket(lua_State *L, int type) {
	struct luasocket *S;

	S = lua_newuserdata(L, sizeof *S);
	*S = *lso_prototype(L);

	S->type = type;

	fifo_init(&S->ibuf.fifo);
	fifo_init(&S->obuf.fifo);

	if (S->onerror != LUA_NOREF && S->onerror != LUA_REFNIL) {
		cqs_getref(L, S->onerror);
		S->onerror = LUA_NOREF;
		cqs_ref(L, &S->onerror);
	}

#if defined LUA_RIDX_MAINTHREAD
	lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_MAINTHREAD);
	S->mainthread = lua_tothread(L, -1);
	lua_pop(L, 1);
#endif

	luaL_getmetatable(L, LSO_CLASS);
	lua_setmetatable(L, -2);

	return S;
} /* lso_newsocket() */


static lso_error_t lso_adjbuf(struct fifo *buf, size_t size) {
	if (size == LSO_INFSIZ)
		return 0;

	return fifo_realloc(buf, size);
} /* lso_adjbuf() */

static lso_error_t lso_adjbufs(struct luasocket *S) {
	int error;

	if ((error = lso_adjbuf(&S->ibuf.fifo, S->ibuf.bufsiz)))
		return error;

	if ((error = lso_adjbuf(&S->obuf.fifo, S->obuf.bufsiz)))
		return error;

	return 0;
} /* lso_adjbufs() */


static lso_error_t lso_prepsocket(struct luasocket *S) {
	return lso_adjbufs(S);
} /* lso_prepsocket() */


static lso_error_t lso_doflush(struct luasocket *, int);

static lso_error_t lso_checktodo(struct luasocket *S) {
	int todo, error;

	while ((todo = (S->todo & ~S->done))) {
		if (todo & LSO_DO_FLUSH) {
			so_clear(S->socket);

			if ((error = lso_doflush(S, LSO_NOBUF)))
				return error;

			S->done |= LSO_DO_FLUSH;
		} else if (todo & LSO_DO_STARTTLS) {
			so_clear(S->socket);

			if (!S->tls.once) {
				S->tls.once = 1;

				if (S->ibuf.mode & LSO_PUSHBACK)
					fifo_rvec(&S->ibuf.fifo, &S->tls.config.pushback, 1);

				error = so_starttls(S->socket, &S->tls.config);

				if (S->ibuf.mode & LSO_PUSHBACK) {
					fifo_purge(&S->ibuf.fifo);
					S->ibuf.eom = 0;
				}
			} else {
				error = so_starttls(S->socket, NULL);
			}

			if (S->tls.config.context) {
				SSL_CTX_free(S->tls.config.context);
				S->tls.config.context = NULL;
			}

			if (error)
				return error;

			S->done |= LSO_DO_STARTTLS;
		}
	}

	return 0;
} /* lso_checktodo() */


static lso_nargs_t lso_connect2(lua_State *L) {
	const char *host NOTUSED = NULL, *port NOTUSED = NULL;
	const char *path = NULL;
	struct so_options opts;
	struct luasocket *S;
	size_t plen;
	int family, type, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		lua_getfield(L, 1, "family");
		family = luaL_optinteger(L, -1, AF_UNSPEC);
		lua_pop(L, 1);

		lua_getfield(L, 1, "type");
		type = luaL_optinteger(L, -1, SOCK_STREAM);
		lua_pop(L, 1);

		if (lso_getfield(L, 1, "path")) {
			path = luaL_checklstring(L, -1, &plen);
			family = AF_UNIX;
		} else {
			lua_getfield(L, 1, "host");
			host = luaL_checkstring(L, -1);
			lua_getfield(L, 1, "port");
			port = luaL_checkstring(L, -1);
		}
	} else {
		opts = *so_opts();
		host = luaL_checkstring(L, 1);
		port = luaL_checkstring(L, 2);
		family = luaL_optinteger(L, 3, AF_UNSPEC);
		type = luaL_optinteger(L, 4, SOCK_STREAM);
	}

	S = lso_newsocket(L, type);

	opts.fd_close.arg = S;
	opts.fd_close.cb = &lso_closefd;

	if (path) {
		struct sockaddr_un sun;

		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_UNIX;
		memcpy(sun.sun_path, path, MIN(plen, sizeof sun.sun_path));

		if (!(S->socket = so_dial((struct sockaddr *)&sun, type, &opts, &error)))
			goto error;
	} else {
		if (!(S->socket = so_open(host, port, 0, family, type, &opts, &error)))
			goto error;
	}

	if ((error = lso_prepsocket(S)))
		goto error;

	(void)so_connect(S->socket);

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_connect2() */


static lso_nargs_t lso_connect1(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int error;

	so_clear(S->socket);

	if (!(error = so_connect(S->socket))) {
		lua_pushvalue(L, 1);

		return 1;
	} else {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}
} /* lso_connect1() */


static lso_nargs_t lso_listen2(lua_State *L) {
	const char *host NOTUSED = NULL, *port NOTUSED = NULL;
	const char *path = NULL;
	struct so_options opts;
	struct luasocket *S;
	size_t plen;
	int family, type, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		lua_getfield(L, 1, "family");
		family = luaL_optinteger(L, -1, AF_UNSPEC);
		lua_pop(L, 1);

		lua_getfield(L, 1, "type");
		type = luaL_optinteger(L, -1, SOCK_STREAM);
		lua_pop(L, 1);

		if (lso_getfield(L, 1, "path")) {
			path = luaL_checklstring(L, -1, &plen);
			family = AF_UNIX;
		} else {
			lua_getfield(L, 1, "host");
			host = luaL_checkstring(L, -1);
			lua_getfield(L, 1, "port");
			port = luaL_checkstring(L, -1);
		}
	} else {
		opts = *so_opts();
		host = luaL_checkstring(L, 1);
		port = luaL_checkstring(L, 2);
		family = luaL_optinteger(L, 3, AF_UNSPEC);
		type = luaL_optinteger(L, 4, SOCK_STREAM);
	}

	S = lso_newsocket(L, type);

	opts.fd_close.arg = S;
	opts.fd_close.cb = &lso_closefd;

	if (path) {
		struct sockaddr_un sun;

		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_UNIX;
		memcpy(sun.sun_path, path, MIN(plen, sizeof sun.sun_path));

		if (!(S->socket = so_dial((struct sockaddr *)&sun, type, &opts, &error)))
			goto error;
	} else {
		if (!(S->socket = so_open(host, port, 0, family, type, &opts, &error)))
			goto error;
	}

	if ((error = lso_prepsocket(S)))
		goto error;

	(void)so_listen(S->socket);

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_listen2() */


static lso_nargs_t lso_listen1(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int error;

	so_clear(S->socket);

	if (!(error = so_listen(S->socket))) {
		lua_pushvalue(L, 1);

		return 1;
	} else {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}
} /* lso_listen1() */


/* luasec compat */
#define LSEC_MODE_INVALID 0
#define LSEC_MODE_SERVER  1
#define LSEC_MODE_CLIENT  2

typedef struct {
	SSL_CTX *context;
	lua_State *L;
	DH *dh_param;
	int mode;
} lsec_context;


static lso_nargs_t lso_starttls(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	SSL_CTX **ctx;
	int error;

	/*
	 * NB: short-circuit if we've already started so we don't
	 * unnecessarily check for or take a reference to the SSL_CTX
	 * object.
	 */
	if ((S->todo & LSO_DO_STARTTLS))
		goto check;

	if ((ctx = luaL_testudata(L, 2, "SSL_CTX*"))) {
		/* accept-mode check handled by so_starttls() */
	} else if ((ctx = luaL_testudata(L, 2, "SSL:Context"))) { /* luasec compatability */
		luaL_argcheck(L, ((lsec_context*)ctx)->mode != LSEC_MODE_INVALID, 2, "invalid mode");
		so_setbool(&S->tls.config.accept, ((((lsec_context*)ctx)->mode) == LSEC_MODE_SERVER));
	}

	if (ctx && *ctx && *ctx != S->tls.config.context) {
		if (S->tls.config.context)
			SSL_CTX_free(S->tls.config.context);

		SSL_CTX_up_ref(*ctx);
		S->tls.config.context = *ctx;
	}

	S->todo |= LSO_DO_STARTTLS;

	if (S->obuf.mode & LSO_AUTOFLUSH)
		S->todo |= LSO_DO_FLUSH;
check:
	if ((error = lso_checktodo(S)))
		goto error;

	lua_pushvalue(L, 1);

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_starttls() */


static lso_nargs_t lso_checktls(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	SSL **ssl;

	ssl = lua_newuserdata(L, sizeof *ssl);

	if (!(*ssl = so_checktls(S->socket)))
		return 0;

	luaL_getmetatable(L, "SSL*");

	if (lua_isnil(L, -1))
		return 0;

	lua_setmetatable(L, -2);

	SSL_up_ref(*ssl);

	return 1;
} /* lso_checktls() */


lso_error_t cqs_socket_fdopen(lua_State *L, int fd, const struct so_options *_opts) {
	struct so_options opts = *((_opts)? _opts : so_opts());
	struct luasocket *S;
	int type = SOCK_STREAM, error;

	if (0 != getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &(socklen_t){ sizeof type })) {
		switch (errno) {
		case ENOTSOCK:
		case EOPNOTSUPP:
			break;
		default:
			goto syerr;
		}
	}

	S = lso_newsocket(L, type);

	if ((error = lso_prepsocket(S)))
		goto error;

	opts.fd_close.arg = S;
	opts.fd_close.cb = &lso_closefd;

	if (!(S->socket = so_fdopen(fd, &opts, &error)))
		goto error;

	return 0;
syerr:
	error = errno;
error:
	lua_pop(L, 1);

	return error;
} /* cqs_socket_fdopen() */


static lso_nargs_t lso_dup(lua_State *L) {
	struct so_options opts;
	int ofd, fd = -1, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		if (!lso_altfield(L, 1, "fd", "file", "socket"))
			lua_rawgeti(L, 1, 1);

		ofd = lso_tofileno(L, -1);

		lua_pop(L, 1);
	} else {
		opts = *so_opts();
		ofd = lso_tofileno(L, 1);
	}

	if (ofd < 0)
		goto badfd;

#if defined F_DUPFD_CLOEXEC
	if (-1 == (fd = fcntl(ofd, F_DUPFD_CLOEXEC, 0)))
		goto syerr;
#else
	if (-1 == (fd = dup(ofd)))
		goto syerr;
#endif

	if ((error = cqs_socket_fdopen(L, fd, &opts)))
		goto error;

	return 1;
badfd:
	error = EBADF;
	goto error;
syerr:
	error = errno;
error:
	cqs_closefd(&fd);

	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_dup() */


/*
 * NOTE: Only permit integer descriptors to mitigate the risk that we wrap a
 * descriptor still owned by a GC-able object. Cf. socket.dup.
 */
static lso_nargs_t lso_fdopen(lua_State *L) {
	struct so_options opts;
	int fd, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		if (lso_altfield(L, 1, "fd")) {
			fd = luaL_checkint(L, -1);
		} else {
			lua_rawgeti(L, 1, 1);
			fd = luaL_checkint(L, -1);
		}

		lua_pop(L, 1);
	} else {
		opts = *so_opts();
		fd = luaL_checkint(L, 1);
	}

	if (fd < 0)
		goto badfd;

	if ((error = cqs_socket_fdopen(L, fd, &opts)))
		goto error;

	return 1;
badfd:
	error = EBADF;
	goto error;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_fdopen() */


static lso_nargs_t lso_pair(lua_State *L) {
	struct luasocket *a = NULL, *b = NULL;
	struct so_options opts;
	int fd[2] = { -1, -1 };
	int type, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		lua_getfield(L, 1, "type");
		type = luaL_optinteger(L, -1, SOCK_STREAM);
		lua_pop(L, 1);
	} else {
		opts = *so_opts();
		type = luaL_optinteger(L, 1, SOCK_STREAM);
	}

	a = lso_newsocket(L, type);
	b = lso_newsocket(L, type);

#if defined SOCK_CLOEXEC
	if (0 != socketpair(AF_UNIX, type|SOCK_CLOEXEC, PF_UNSPEC, fd))
		goto syerr;
#else
	if (0 != socketpair(AF_UNIX, type, PF_UNSPEC, fd))
		goto syerr;
#endif

	opts.fd_close.arg = a;
	opts.fd_close.cb = &lso_closefd;

	if (!(a->socket = so_fdopen(fd[0], &opts, &error)))
		goto error;

	fd[0] = -1;

	if ((error = lso_prepsocket(a)))
		goto error;

	opts.fd_close.arg = b;
	opts.fd_close.cb = &lso_closefd;

	if (!(b->socket = so_fdopen(fd[1], &opts, &error)))
		goto error;

	fd[1] = -1;

	if ((error = lso_prepsocket(b)))
		goto error;

	return 2;
syerr:
	error = errno;
error:
	cqs_closefd(&fd[0]);
	cqs_closefd(&fd[1]);

	lua_pushnil(L);
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 3;
} /* lso_pair() */


static int lso_checkvbuf(struct lua_State *L, int index) {
	switch (luaL_checkoption(L, index, "line", (const char *[]){ "line", "full", "nobuf", "no", NULL })) {
	case 0: /* "line" */
		return LSO_LINEBUF;
	case 1: /* "full" */
		return LSO_FULLBUF;
	case 2: /* "nobuf" */
		/* FALL THROUGH */
	case 3: /* "no" */
		/* FALL THROUGH */
	default:
		return LSO_NOBUF;
	}
} /* lso_checkvbuf() */


static lso_nargs_t lso_setvbuf_(struct lua_State *L, struct luasocket *S, int modeidx, int bufidx) {
	lso_pushmode(L, S->obuf.mode, LSO_WRMASK, 1);
	lua_pushinteger(L, S->obuf.bufsiz);

	S->obuf.mode = lso_checkvbuf(L, modeidx) | (S->obuf.mode & ~LSO_ALLBUF);

	if (S->obuf.mode & (LSO_LINEBUF|LSO_FULLBUF))
		S->obuf.bufsiz = lso_optsize(L, bufidx, LSO_BUFSIZ);

	return 2;
} /* lso_setvbuf_() */


static lso_nargs_t lso_setvbuf2(struct lua_State *L) {
	lua_settop(L, 2);

	return lso_setvbuf_(L, lso_prototype(L), 1, 2);
} /* lso_setvbuf2() */


static lso_nargs_t lso_setvbuf3(struct lua_State *L) {
	lua_settop(L, 3);

	return lso_setvbuf_(L, lso_checkself(L, 1), 2, 3);
} /* lso_setvbuf3() */


static lso_nargs_t lso_setmode_(struct lua_State *L, struct luasocket *S, int ridx, int widx) {
	lso_pushmode(L, S->ibuf.mode, LSO_RDMASK, 0);
	lso_pushmode(L, S->obuf.mode, LSO_WRMASK, 0);

	if (!lua_isnil(L, ridx))
		S->ibuf.mode = LSO_RDMASK & lso_imode(luaL_checkstring(L, ridx), LSO_INITMODE);

	if (!lua_isnil(L, widx))
		S->obuf.mode = LSO_WRMASK & lso_imode(luaL_checkstring(L, widx), LSO_INITMODE);

	return 2;
} /* lso_setmode_() */


static lso_nargs_t lso_setmode2(struct lua_State *L) {
	lua_settop(L, 2);

	return lso_setmode_(L, lso_prototype(L), 1, 2);
} /* lso_setmode2() */


static lso_nargs_t lso_setmode3(struct lua_State *L) {
	lua_settop(L, 3);

	return lso_setmode_(L, lso_checkself(L, 1), 2, 3);
} /* lso_setmode3() */


static lso_nargs_t lso_setbufsiz_(struct lua_State *L, struct luasocket *S, int ridx, int widx) {
	lso_pushsize(L, S->ibuf.bufsiz);
	lso_pushsize(L, S->obuf.bufsiz);

	S->ibuf.bufsiz = lso_optsize(L, ridx, S->ibuf.bufsiz);
	S->obuf.bufsiz = lso_optsize(L, widx, S->obuf.bufsiz);

	return 2;
} /* lso_setbufsiz_() */


static lso_nargs_t lso_setbufsiz2(struct lua_State *L) {
	lua_settop(L, 2);

	return lso_setbufsiz_(L, lso_prototype(L), 1, 2);
} /* lso_setbufsiz2() */


static lso_nargs_t lso_setbufsiz3(struct lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int n, error;

	lua_settop(L, 3);

	n = lso_setbufsiz_(L, S, 2, 3);

	if ((error = lso_adjbufs(S)))
		goto error;

	return n;
error:
	lua_pushnil(L);
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 3;
} /* lso_setbufsiz3() */


static lso_nargs_t lso_setmaxline_(struct lua_State *L, struct luasocket *S, int ridx, int widx) {
	lso_pushsize(L, S->ibuf.maxline);
	lso_pushsize(L, S->obuf.maxline);

	S->ibuf.maxline = lso_optsize(L, ridx, S->ibuf.maxline);
	S->obuf.maxline = lso_optsize(L, widx, S->obuf.maxline);

	return 2;
} /* lso_setmaxline_() */


static lso_nargs_t lso_setmaxline2(struct lua_State *L) {
	lua_settop(L, 2);

	return lso_setmaxline_(L, lso_prototype(L), 1, 2);
} /* lso_setmaxline2() */


static lso_nargs_t lso_setmaxline3(struct lua_State *L) {
	lua_settop(L, 3);

	return lso_setmaxline_(L, lso_checkself(L, 1), 2, 3);
} /* lso_setmaxline3() */


static lso_nargs_t lso_settimeout_(struct lua_State *L, struct luasocket *S, int index) {
	double timeout;

	if (isnormal(S->timeout) || S->timeout == 0) {
		lua_pushnumber(L, S->timeout);
	} else {
		lua_pushnil(L);
	}

	timeout = luaL_optnumber(L, index, NAN);

	S->timeout = (isnormal(timeout) || timeout == 0)? timeout : NAN;

	return 1;
} /* lso_settimeout_() */


static lso_nargs_t lso_settimeout1(struct lua_State *L) {
	lua_settop(L, 1);

	return lso_settimeout_(L, lso_prototype(L), 1);
} /* lso_settimeout1() */


static lso_nargs_t lso_settimeout2(struct lua_State *L) {
	lua_settop(L, 2);

	return lso_settimeout_(L, lso_checkself(L, 1), 2);
} /* lso_settimeout2() */


static lso_nargs_t lso_setmaxerrs_(struct lua_State *L, struct luasocket *S, int index) {
	const char *what = "rw";
	int nret = 0;

	if (lua_type(L, index) == LUA_TSTRING) {
		what = luaL_checkstring(L, index);
		index++;
	}

	for (; *what; what++) {
		switch (*what) {
		case 'r':
			lua_pushinteger(L, S->ibuf.maxerrs);
			nret++;

			S->ibuf.maxerrs = luaL_optunsigned(L, index, S->ibuf.maxerrs);

			break;
		case 'w':
			lua_pushinteger(L, S->obuf.maxerrs);
			nret++;

			S->obuf.maxerrs = luaL_optunsigned(L, index, S->obuf.maxerrs);

			break;
		default:
			return luaL_argerror(L, 1, lua_pushfstring(L, "%s: %c: only `r' or `w' accepted", what, *what));
		}
	}

	return nret;
} /* lso_setmaxerrs_() */


static lso_nargs_t lso_setmaxerrs1(struct lua_State *L) {
	return lso_setmaxerrs_(L, lso_prototype(L), 1);
} /* lso_setmaxerrs1() */


static lso_nargs_t lso_setmaxerrs2(struct lua_State *L) {
	return lso_setmaxerrs_(L, lso_checkself(L, 1), 2);
} /* lso_setmaxerrs2() */


static lso_nargs_t lso_onerror_(struct lua_State *L, struct luasocket *S, int fidx) {
	cqs_getref(L, S->onerror);

	if (lua_gettop(L) > fidx) {
		if (!lua_isnil(L, fidx))
			luaL_checktype(L, fidx, LUA_TFUNCTION);
		lua_pushvalue(L, fidx);
		cqs_ref(L, &S->onerror);
	}

	return 1;
} /* lso_onerror_() */


static lso_nargs_t lso_onerror1(struct lua_State *L) {
	return lso_onerror_(L, lso_prototype(L), 1);
} /* lso_onerror1() */


static lso_nargs_t lso_onerror2(struct lua_State *L) {
	return lso_onerror_(L, lso_checkself(L, 1), 2);
} /* lso_onerror2() */


static void lso_pusherror(struct lua_State *L, int error) {
	if (error)
		lua_pushinteger(L, error);
	else
		lua_pushnil(L);
} /* lso_pusherror() */


static lso_nargs_t lso_seterror_(struct lua_State *L, struct luasocket *S, const char *what, int error) {
	int nret = 0;

	for (; *what; what++) {
		switch (*what) {
		case 'r':
			lso_pusherror(L, S->ibuf.error);
			nret++;

			if (!(S->ibuf.error = error))
				S->ibuf.numerrs = 0;

			break;
		case 'w':
			lso_pusherror(L, S->obuf.error);
			nret++;

			if (!(S->obuf.error = error))
				S->obuf.numerrs = 0;

			break;
		default:
			return luaL_argerror(L, 2, lua_pushfstring(L, "%s: %c: only `r' or `w' accepted", what, *what));
		} /* switch() */
	} /* for() */

	return nret;
} /* lso_seterror_() */


static lso_nargs_t lso_seterror(struct lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const char *what = luaL_checkstring(L, 2);
	int error = luaL_optint(L, 3, 0);

	return lso_seterror_(L, S, what, error);
} /* lso_seterror() */


static lso_nargs_t lso_error(struct lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const char *what = luaL_optstring(L, 2, "rw");
	int nret = 0;

	for (; *what; what++) {
		switch (*what) {
		case 'r':
			lso_pusherror(L, S->ibuf.error);
			nret++;

			break;
		case 'w':
			lso_pusherror(L, S->obuf.error);
			nret++;

			break;
		default:
			return luaL_argerror(L, 2, lua_pushfstring(L, "%s: %c: only `r' or `w' accepted", what, *what));
		} /* switch() */
	} /* for() */

	return nret;
} /* lso_error() */


static lso_nargs_t lso_clearerr(struct lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const char *what = luaL_optstring(L, 2, "rw");

	return lso_seterror_(L, S, what, 0);
} /* lso_clearerr() */


static lso_error_t lso_fill(struct luasocket *S, size_t limit) {
	struct iovec iov;
	size_t prepbuf, count;
	int error;

	if (S->ibuf.eom && fifo_rlen(&S->ibuf.fifo) > 0)
		return 0;

	prepbuf = (S->type == SOCK_DGRAM)? (SO_MIN(limit, 65536)) : 1;

	while (fifo_rlen(&S->ibuf.fifo) < limit) {
		if ((error = fifo_wbuf(&S->ibuf.fifo, &iov, prepbuf)))
			return error;

		if ((count = so_read(S->socket, iov.iov_base, iov.iov_len, &error))) {
			fifo_update(&S->ibuf.fifo, count);

			if (S->type == SOCK_DGRAM || S->type == SOCK_SEQPACKET) {
				S->ibuf.eom = 1;

				return 0;
			}
		} else {
			switch (error) {
			case EPIPE:
				S->ibuf.eof = 1;
			default:
				return error;
			} /* switch() */
		}
	}

	return 0;
} /* lso_fill() */


static _Bool lso_nomore(struct luasocket *S, size_t limit) {
	return S->ibuf.eof || S->ibuf.eom || fifo_rlen(&S->ibuf.fifo) >= limit;
} /* lso_nomore() */


static lso_error_t lso_asserterror(int error) {
	return (error)? error : EFAULT;
} /* lso_asserterror() */


static lso_error_t lso_getline(struct luasocket *S, struct iovec *iov) {
	int error;

	while (!fifo_lvec(&S->ibuf.fifo, iov)) {
		error = lso_fill(S, S->ibuf.maxline);

		if (fifo_lvec(&S->ibuf.fifo, iov))
			break;

		if (fifo_rlen(&S->ibuf.fifo) > 0 && lso_nomore(S, S->ibuf.maxline)) {
			fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

			break;
		}

		return lso_asserterror(error);
	}

	iov->iov_len = MIN(iov->iov_len, S->ibuf.maxline);

	return 0;
} /* lso_getline() */


static lso_error_t lso_getheader(struct luasocket *S, struct iovec *iov) {
	size_t eoh;
	int error;

	fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

	if ((size_t)-1 == (eoh = iov_eoh(iov, lso_nomore(S, S->ibuf.maxline), 0, &error)))
		goto error;

	if (!eoh || eoh > iov->iov_len) {
		error = lso_fill(S, S->ibuf.maxline);

		fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

		if ((size_t)-1 == (eoh = iov_eoh(iov, lso_nomore(S, S->ibuf.maxline), 0, &error)))
			goto error;
		else if (!eoh)
			goto nomore;
		else if (eoh > iov->iov_len)
			goto error; /* lso_fill should have returned error */
	}

	iov->iov_len = eoh;

	return 0;
nomore:
	iov->iov_len = 0;

	return 0;
error:
	return lso_asserterror(error);
} /* lso_getheader() */


static lso_error_t lso_getbody(struct luasocket *S, struct iovec *iov, int *eom, const char *eob, size_t eoblen, int mode) {
	size_t bufsiz, maxbuf, n;
	int error;

	bufsiz = (mode & LSO_TEXT)? MAX(S->ibuf.bufsiz, S->ibuf.maxline) : S->ibuf.bufsiz;
	bufsiz = MAX(bufsiz, 2); /* see comment in text-mode handling below wrt >=2 */

	/*
	 * Adjust window. We need at least 1 + "\r\n" + eoblen to make
	 * forward progress. But we actually want to return bufsiz-sized
	 * intermediate chunks. So we want a temporary buffer of bufsiz +
	 * "\r\n" + eoblen.
	 */
	if ((error = cqs_addzu(&maxbuf, bufsiz, 2)))
		return error;
	if ((error = cqs_addzu(&maxbuf, maxbuf, eoblen)))
		return error;

	error = lso_fill(S, maxbuf);

	fifo_slice(&S->ibuf.fifo, iov, 0, maxbuf);

	if ((n = iov_eob(iov, eob, eoblen))) {
		iov->iov_len = n - eoblen; /* n >= eoblen */

		*eom = 1;
	} else if (iov->iov_len >= maxbuf) {
		/*
		 * Because maxbuf is >= bufsiz + 2 + eoblen we can be sure
		 * that returning bufsiz bytes won't cause problems trimming
		 * the \r\n preceding the boundary marker. It's inelegant
		 * but very simple. In the case of a stall or broken
		 * connection we may be leaving more bytes in the buffer
		 * than strictly necessary, but in those cases something is
		 * broken, anyhow.
		 */
		iov->iov_len = bufsiz;

		if (mode & LSO_TEXT) {
			iov->iov_len = iov_eol(iov);

			/* trim if might be part of \r\n sequence */
			if (iov_lc(iov) == '\r')
				--iov->iov_len;
			/*
			 * NOTE: we guaranteed above that bufsiz >= 2 so we
			 * don't accidentally return an empty string if we
			 * trimmed a \r here.
			 */
		}
	}

	return 0;
} /* lso_getbody() */


static lso_error_t lso_getblock(struct luasocket *S, struct iovec *iov, size_t minbuf, size_t maxbuf, int mode) {
	int error;

	if (mode & LSO_TEXT) {
		size_t fillsz = maxbuf, n;

		do {
			error = lso_fill(S, fillsz);

			fifo_slice(&S->ibuf.fifo, iov, 0, -1);

			if ((size_t)-1 == (n = iov_eot(iov, minbuf, maxbuf, (S->ibuf.eof || S->ibuf.eom), &error))) {
				goto error;
			} else if (n > iov->iov_len) {
				if (fillsz < n)
					error = 0;

				fillsz = n;
			} else {
				iov->iov_len = n;

				return 0;
			}
		} while (!error);
	} else {
		error = lso_fill(S, maxbuf);

		if (fifo_slice(&S->ibuf.fifo, iov, 0, maxbuf) >= minbuf)
			return 0;

		if ((S->ibuf.eof || S->ibuf.eom) && iov->iov_len > 0)
			return 0;
	}

error:
	return lso_asserterror(error);
} /* lso_getblock() */


struct lso_rcvop {
	int index;

	enum {
		LSO_NONE,
		LSO_NUMBER,
		LSO_SLURP,
		LSO_CHOMP,
		LSO_LINE,
		LSO_FIELD,
		LSO_HEADER,
		LSO_BODY,
		LSO_BLOCK,
		LSO_LIMIT,
	} type;

	int mode;

	EXTENSION union {
		size_t size;

		struct {
			const char *eob;
			size_t eoblen;
		} body;
	};
}; /* struct lso_rcvop */


static struct lso_rcvop lso_checkrcvop(lua_State *L, int index, int mode) {
	struct lso_rcvop op = { index, LSO_NONE, mode };
	lua_Number size;

	if (!lua_isnumber(L, index)) {
		size_t len;
		const char *fmt = luaL_optlstring(L, index, "*l", &len);

		if (fmt[0] == '*' && len == 2) {
			switch (fmt[1]) {
			case 'n':
				op.type = LSO_NUMBER;
				break;
			case 'a':
				op.type = LSO_SLURP;
				break;
			case 'l':
				op.type = LSO_CHOMP;
				break;
			case 'L':
				op.type = LSO_LINE;
				break;
			case 'h':
				op.type = LSO_FIELD;
				break;
			case 'H':
				op.type = LSO_HEADER;
				break;
			}
		} else if (fmt[0] == '-' && fmt[1] == '-') {
			op.type = LSO_BODY;
			op.body.eob = fmt;
			op.body.eoblen = len;
		}
	} else {
		if ((size = luaL_checknumber(L, index)) < 0) {
			op.type = LSO_LIMIT;
			op.size = -size;
		} else {
			op.type = LSO_BLOCK;
			op.size = size;
		}
	}

	if (op.type == LSO_NONE)
		luaL_argerror(L, index, lua_pushfstring(L, "invalid format %s", luaL_checkstring(L, index)));

	return op;
} /* lso_checkrcvop() */


#define LSO_CHECKERRS(L, iobuf) do { \
	if (!(iobuf).error) \
		return 0; \
	if (++(iobuf).numerrs > (iobuf).maxerrs) \
		luaL_error((L), "exceeded unchecked error limit (%s)", cqs_strerror((iobuf).error)); \
	return (iobuf).error; \
} while (0)

static lso_error_t lso_checkrcverrs(lua_State *L, struct luasocket *S) {
	LSO_CHECKERRS(L, S->ibuf);
} /* lso_checkrcverrs() */

static lso_error_t lso_checksnderrs(lua_State *L, struct luasocket *S) {
	LSO_CHECKERRS(L, S->obuf);
} /* lso_checksnderrs() */


static lso_error_t lso_preprcv(lua_State *L, struct luasocket *S) {
	int error;

	if ((error = lso_checkrcverrs(L, S)))
		return error;

	if ((error = lso_checktodo(S)))
		return error;

	so_clear(S->socket);

	if (S->obuf.mode & LSO_AUTOFLUSH) {
		switch ((error = lso_doflush(S, LSO_NOBUF))) {
		case EAGAIN:
			break;
		case EPIPE:
			break;
		default:
			return error;
		}
	}

	return 0;
} /* lso_preprcv() */

static lso_error_t lso_prepsnd(lua_State *L, struct luasocket *S) {
	int error;

	if ((error = lso_checksnderrs(L, S)))
		return error;

	return lso_checktodo(S);
} /* lso_prepsnd() */


static lso_nargs_t lso_recv3(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	struct lso_rcvop op;
	struct iovec iov;
	size_t count;
	int error;

	if ((error = lso_preprcv(L, S)))
		goto error;

	lua_settop(L, 3);

	op = lso_checkrcvop(L, 2, lso_imode(luaL_optstring(L, 3, ""), S->ibuf.mode));

	switch (op.type) {
	case LSO_NUMBER:
		return luaL_argerror(L, op.index, "*n not implemented yet");
	case LSO_SLURP:
		error = lso_fill(S, (size_t)-1);

		if (!(S->ibuf.eom || S->ibuf.eof))
			goto error;

		fifo_rvec(&S->ibuf.fifo, &iov, 1);

		if ((count = iov.iov_len)) {
			if (op.mode & LSO_TEXT)
				iov_trimcr(&iov, 0);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	case LSO_CHOMP:
		if ((error = lso_getline(S, &iov)))
			goto error;

		count = iov.iov_len;

		if (op.mode & LSO_TEXT)
			iov_trimcr(&iov, 1);

		if (iov_lc(&iov) == '\n')
			--iov.iov_len;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, count);

		break;
	case LSO_LINE:
		if ((error = lso_getline(S, &iov)))
			goto error;

		count = iov.iov_len;

		if (op.mode & LSO_TEXT)
			iov_trimcr(&iov, 1);

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, count);

		break;
	case LSO_FIELD:
		if ((error = lso_getheader(S, &iov)))
			goto error;

		if ((count = iov.iov_len)) {
			iov_trimcrlf(&iov, 0);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	case LSO_HEADER:
		if ((error = lso_getheader(S, &iov)))
			goto error;

		if ((count = iov.iov_len)) {
			if (op.mode & LSO_TEXT)
				iov_trimcr(&iov, 0);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	case LSO_BODY: {
		int eom = 0; /* it would be confusing to overload ibuf.eom */

		if ((error = lso_getbody(S, &iov, &eom, op.body.eob, op.body.eoblen, op.mode)))
			goto error;

		if ((count = iov.iov_len)) {
			if (eom) {
				/* trim any \r\n preceding the boundary */
				iov_trimcrlf(&iov, 1);

				if (op.mode & LSO_TEXT)
					iov_trimcr(&iov, 0);

				if (iov.iov_len)
					lua_pushlstring(L, iov.iov_base, iov.iov_len);
				else
					lua_pushnil(L);
			} else {
				if (op.mode & LSO_TEXT)
					iov_trimcr(&iov, 0);

				lua_pushlstring(L, iov.iov_base, iov.iov_len);
			}

			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	}
	case LSO_BLOCK:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			break;
		}

		if ((error = lso_getblock(S, &iov, op.size, op.size, op.mode)))
			goto error;

		if ((count = iov.iov_len)) {
			if (op.mode & LSO_TEXT)
				iov_trimcr(&iov, 0);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	case LSO_LIMIT:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			break;
		}

		if ((error = lso_getblock(S, &iov, 1, op.size, op.mode)))
			goto error;

		if ((count = iov.iov_len)) {
			if (op.mode & LSO_TEXT)
				iov_trimcr(&iov, 0);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	default:
		error = EFAULT;

		goto error;
	} /* switch(op) */

	if (!fifo_rlen(&S->ibuf.fifo))
		S->ibuf.eom = 0;

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, lso_asserterror(error));

	return 2;
} /* lso_recv3() */


static lso_nargs_t lso_unget2(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const void *src;
	size_t len;
	struct iovec iov;
	int error;

	src = luaL_checklstring(L, 2, &len);

	if ((error = fifo_grow(&S->ibuf.fifo, len)))
		goto error;

	fifo_rewind(&S->ibuf.fifo, len);
	fifo_slice(&S->ibuf.fifo, &iov, 0, len);
	memcpy(iov.iov_base, src, len);

	S->ibuf.eof = 0;

	lua_pushboolean(L, 1);

	return 1;
error:
	lua_pushboolean(L, 0);
	lua_pushinteger(L, error);

	return 2;
} /* lso_unget2() */


static lso_error_t lso_doflush(struct luasocket *S, int mode) {
	size_t amount = 0, n;
	struct iovec iov;
	int error;

	if (mode & LSO_LINEBUF) {
		if (S->obuf.eol > 0) {
			amount = S->obuf.eol;
		} else if (fifo_rlen(&S->obuf.fifo) >= S->obuf.maxline) {
			amount = S->obuf.maxline;
		}
	} else if (mode & LSO_FULLBUF) {
		amount = fifo_rlen(&S->obuf.fifo);
		amount -= amount % S->obuf.bufsiz;
	} else if (mode & LSO_NOBUF) {
		amount = fifo_rlen(&S->obuf.fifo);
	}

	while (amount) {
		if (!fifo_slice(&S->obuf.fifo, &iov, 0, amount))
			break; /* should never happen */

		if (!(n = so_write(S->socket, iov.iov_base, iov.iov_len, &error)))
			goto error;

		fifo_discard(&S->obuf.fifo, n);
		amount -= n;
		S->obuf.eol -= MIN(S->obuf.eol, n);
	}

	return 0;
error:
	switch (error) {
	case EPIPE:
		S->obuf.eof = 1;

		break;
	} /* switch() */

	return error;
} /* lso_doflush() */


static lso_nargs_t lso_send5(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const unsigned char *src, *lf;
	size_t tp, p, pe, end, n;
	int mode, byline, error;

	if ((error = lso_prepsnd(L, S))) {
		lua_pushinteger(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}

	lua_settop(L, 5);

	src = (const void *)luaL_checklstring(L, 2, &end);
	tp = lso_checksize(L, 3) - 1;
	pe = lso_checksize(L, 4);
	mode = lso_imode(luaL_optstring(L, 5, ""), S->obuf.mode);
	byline = (mode & (LSO_TEXT|LSO_LINEBUF)) || (S->obuf.mode & LSO_LINEBUF);

	luaL_argcheck(L, tp <= end, 3, "start index beyond object boundary");
	luaL_argcheck(L, pe <= end, 4, "end index beyond object boundary");

	p = tp;

	so_clear(S->socket);

	while (p < pe) {
		if (byline) {
			n = MIN(pe - p, S->obuf.maxline);

			if ((lf = memchr(&src[p], '\n', n))) {
				n = lf - &src[p];

				if ((error = fifo_write(&S->obuf.fifo, &src[p], n)))
					goto error;

				if ((mode & LSO_TEXT) && (error = fifo_putc(&S->obuf.fifo, '\r')))
					goto error;

				if ((error = fifo_putc(&S->obuf.fifo, '\n')))
					goto error;

				p += n + 1;

				S->obuf.eol = fifo_rlen(&S->obuf.fifo);
			} else {
				if ((error = fifo_write(&S->obuf.fifo, &src[p], n)))
					goto error;

				p += n;
			}
		} else {
			n = MIN(pe - p, LSO_BUFSIZ);

			if ((error = fifo_write(&S->obuf.fifo, &src[p], n)))
				goto error;

			p += n;
		}

		if (fifo_rlen(&S->obuf.fifo) > S->obuf.bufsiz) {
			if ((error = lso_doflush(S, mode)))
				goto error;
		}
	}

	if ((error = lso_doflush(S, mode)))
		goto error;

	lua_pushinteger(L, p - tp);

	return 1;
error:
	lua_pushinteger(L, p - tp);
	lua_pushinteger(L, error);

	return 2;
} /* lso_send5() */


static lso_nargs_t lso_flush(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int mode = lso_imode(luaL_optstring(L, 2, "n"), S->obuf.mode);
	int error;

	if ((error = lso_prepsnd(L, S)) || (error = lso_doflush(S, mode))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* lso_flush() */


static lso_nargs_t lso_uncork(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int error;

	if ((error = so_uncork(S->socket))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* lso_uncork() */


static lso_nargs_t lso_pending(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);

	lua_pushunsigned(L, fifo_rlen(&S->ibuf.fifo));
	lua_pushunsigned(L, fifo_rlen(&S->obuf.fifo));

	return 2;
} /* lso_pending() */


static lso_nargs_t lso_sendfd3(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const void *src;
	size_t len;
	int fd, error;

	if ((error = lso_prepsnd(L, S)))
		goto error;

	lua_settop(L, 3);

	src = luaL_checklstring(L, 2, &len);

	if ((fd = lso_tofileno(L, 3)) < 0)
		goto badfd;

	so_clear(S->socket);

	if ((error = so_sendmsg(S->socket, so_fdmsg(src, len, fd), 0)))
		goto error;

	lua_pushboolean(L, 1);

	return 1;
badfd:
	error = EBADF;
error:
	lua_pushboolean(L, 0);
	lua_pushinteger(L, error);

	return 2;
} /* lso_sendfd3() */


static lso_nargs_t lso_recvfd2(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	size_t bufsiz = luaL_optunsigned(L, 2, S->ibuf.maxline);
	struct msghdr *msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct so_options opts;
	int fd = -1, error;

	if ((error = lso_preprcv(L, S)))
		goto error;

	if ((error = fifo_grow(&S->ibuf.fifo, bufsiz)))
		goto error;

	fifo_wvec(&S->ibuf.fifo, &iov, 1);

	msg = so_fdmsg(iov.iov_base, iov.iov_len, -1);

#if defined MSG_CMSG_CLOEXEC
	if ((error = so_recvmsg(S->socket, msg, MSG_CMSG_CLOEXEC)))
		goto error;
#else
	if ((error = so_recvmsg(S->socket, msg, 0)))
		goto error;
#endif

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		cqs_closefd(&fd);
		memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
	}

	if (msg->msg_flags & (MSG_TRUNC|MSG_CTRUNC))
		goto trunc;

	if (msg->msg_iovlen > 0 && msg->msg_iov[0].iov_len > 0)
		lua_pushlstring(L, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
	else
		lua_pushliteral(L, "");

	if (fd == -1)
		lua_pushnil(L);
	else if ((error = cqs_socket_fdopen(L, fd, so_opts())))
		goto error;

	return 2;
trunc:
	error = ENOBUFS;
error:
	cqs_closefd(&fd);

	lua_pushnil(L);
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 3;
} /* lso_recvfd2() */


static lso_nargs_t lso_pack4(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	lua_Number value;
	unsigned count;
	int mode, error;

	if ((error = lso_prepsnd(L, S)))
		goto error;

	lua_settop(L, 4);

	value = luaL_checknumber(L, 2);
	count = luaL_optunsigned(L, 3, 32);
	mode = lso_imode(luaL_optstring(L, 4, ""), S->obuf.mode);

	if ((error = fifo_pack(&S->obuf.fifo, (unsigned long long)(long long)value, count)))
		goto error;

	so_clear(S->socket);

	if ((error = lso_doflush(S, mode)))
		goto error;

	lua_pushboolean(L, 1);

	return 1;
error:
	lua_pushboolean(L, 0);
	lua_pushinteger(L, error);

	return 2;
} /* lso_pack4() */


static lso_nargs_t lso_unpack2(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	unsigned long long value;
	unsigned count;
	int error;

	if ((error = lso_preprcv(L, S)))
		goto error;

	lua_settop(L, 2);

	count = luaL_optunsigned(L, 2, 32);

	if (fifo_rbits(&S->ibuf.fifo) < count) {
		size_t rem = ((count - fifo_rbits(&S->ibuf.fifo)) + 7U) / 8U;

		if ((error = lso_fill(S, rem))) {
			if (fifo_rbits(&S->ibuf.fifo) < count)
				goto error;
		}
	}

	value = fifo_unpack(&S->ibuf.fifo, count);

	if (value == (unsigned long long)(lua_Integer)value)
		lua_pushinteger(L, (lua_Integer)value);
	else if (value == (unsigned long long)(lua_Number)value)
		lua_pushnumber(L, (lua_Number)value);
	else
		goto range;

	return 1;
range:
	error = ERANGE;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_unpack2() */


static lso_nargs_t lso_fill2(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	size_t size = lso_checksize(L, 2);
	int error;

	if ((error = lso_preprcv(L, S)) || (error = lso_fill(S, size))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}

	lua_pushboolean(L, 1);

	return 1;
} /* lso_fill2() */


static lso_nargs_t lso_clear(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);

	so_clear(S->socket);

	lua_pushboolean(L, 1);

	return 1;
} /* lso_clear() */


int cqs_socket_pollfd(lua_State *L, int index) {
	struct luasocket *S = lso_checkvalid(L, index, lua_touserdata(L, index));

	return so_pollfd(S->socket);
} /* cqs_socket_pollfd() */

static lso_nargs_t lso_pollfd(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);

	lua_pushinteger(L, so_pollfd(S->socket));

	return 1;
} /* lso_pollfd() */


int cqs_socket_events(lua_State *L, int index) {
	struct luasocket *S = lso_checkvalid(L, index, lua_touserdata(L, index));

	return so_events(S->socket);
} /* cqs_socket_events() */

static lso_nargs_t lso_events(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	short events = so_events(S->socket);
	char mode[3], *p = mode;

	if ((events & POLLIN))
		*p++ = 'r';

	if ((events & POLLOUT))
		*p++ = 'w';

	lua_pushlstring(L, mode, p - mode);

	return 1;
} /* lso_events() */


double cqs_socket_timeout(lua_State *L NOTUSED, int index NOTUSED) {
	struct luasocket *S = lso_checkvalid(L, index, lua_touserdata(L, index));

	return S->timeout;
} /* cqs_socket_timeout() */


static lso_nargs_t lso_timeout(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);

	if (isnormal(S->timeout) || S->timeout == 0) {
		lua_pushnumber(L, S->timeout);

		return 1;
	}

	return 0;
} /* lso_timeout() */


static lso_nargs_t lso_shutdown(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int how, error;

	switch (luaL_checkoption(L, 2, "rw", (const char *[]){ "r", "w", "rw", "wr", 0 })) {
	case 0:
		how = SHUT_RD;

		break;
	case 1:
		how = SHUT_WR;

		break;
	default:
		how = SHUT_RDWR;

		break;
	} /* switch() */

	if ((error = so_shutdown(S->socket, how))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* lso_shutdown() */


static lso_nargs_t lso_eof(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const char *which = luaL_optstring(L, 2, "rw");
	int nret = 0;

	for (; *which; which++) {
		switch (*which) {
		case 'r':
			lua_pushboolean(L, S->ibuf.eof);
			nret++;

			break;
		case 'w':
			lua_pushboolean(L, S->obuf.eof);
			nret++;

			break;
		}
	} /* for() */

	return nret;
} /* lso_eof() */


static lso_nargs_t lso_accept(lua_State *L) {
	struct luasocket *A = lso_checkself(L, 1), *S;
	struct so_options opts;
	int fd = -1, error;

	if (lua_istable(L, 2)) {
		opts = lso_checkopts(L, 2);
	} else {
		opts = *so_opts();
	}

	S = lso_newsocket(L, A->type);

	opts.fd_close.arg = S;
	opts.fd_close.cb = &lso_closefd;

	so_clear(A->socket);

	if (-1 == (fd = so_accept(A->socket, 0, 0, &error)))
		goto error;

	if ((error = lso_prepsocket(S)))
		goto error;

	if (!(S->socket = so_fdopen(fd, &opts, &error)))
		goto error;

	return 1;
syerr:
	error = errno;
error:
	cqs_closefd(&fd);
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_accept() */


static lso_nargs_t lso_pushname(lua_State *L, struct sockaddr_storage *ss, socklen_t salen) {
	switch (ss->ss_family) {
	case AF_INET:
		/* FALL THROUGH */
	case AF_INET6:
		lua_pushinteger(L, ss->ss_family);
		lua_pushstring(L, sa_ntoa(ss));
		lua_pushinteger(L, ntohs(*sa_port(ss, SA_PORT_NONE, NULL)));

		return 3;
	case AF_UNIX:
		lua_pushinteger(L, ss->ss_family);

		/* support nameless sockets and Linux's abstract namespace */
		if (salen > offsetof(struct sockaddr_un, sun_path)) {
			struct sockaddr_un *sun = (struct sockaddr_un *)ss;
			char *pe = (char *)sun + SO_MIN(sizeof *sun, salen);
			size_t plen;

			while (pe > sun->sun_path && pe[-1] == '\0')
				--pe;

			if ((plen = (pe - sun->sun_path)) > 0) {
				lua_pushlstring(L, sun->sun_path, plen);
			} else {
				lua_pushnil(L);
			}
		} else {
			lua_pushnil(L);
		}

		return 2;
	default:
		lua_pushinteger(L, ss->ss_family);

		return 1;
	}
} /* lso_pushname() */


static lso_nargs_t lso_peername(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	struct sockaddr_storage ss;
	socklen_t salen = sizeof ss;
	int error;

	memset(&ss, 0, sizeof ss);

	if ((error = so_remoteaddr(S->socket, &ss, &salen))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	return lso_pushname(L, &ss, salen);
} /* lso_peername() */


static lso_nargs_t lso_peereid(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	uid_t uid;
	gid_t gid;
	int error;

	if ((error = so_peereid(S->socket, &uid, &gid))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	lua_pushinteger(L, uid);
	lua_pushinteger(L, gid);

	return 2;
} /* lso_peereid() */


static lso_nargs_t lso_peerpid(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	pid_t pid;
	int error;

	if ((error = so_peerpid(S->socket, &pid))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	lua_pushinteger(L, pid);

	return 1;
} /* lso_peerpid() */


static lso_nargs_t lso_localname(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	struct sockaddr_storage ss;
	socklen_t salen = sizeof ss;
	int error;

	memset(&ss, 0, sizeof ss);

	if ((error = so_localaddr(S->socket, &ss, &salen))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	return lso_pushname(L, &ss, salen);
} /* lso_localname() */


static lso_nargs_t lso_stat(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const struct so_stat *st = so_stat(S->socket);

	lua_newtable(L);

	lua_newtable(L);
	lua_pushinteger(L, st->sent.count);
	lua_setfield(L, -2, "count");
	lua_pushboolean(L, st->sent.eof);
	lua_setfield(L, -2, "eof");
	lua_pushinteger(L, st->sent.time);
	lua_setfield(L, -2, "time");
	lua_setfield(L, -2, "sent");

	lua_newtable(L);
	lua_pushinteger(L, st->rcvd.count);
	lua_setfield(L, -2, "count");
	lua_pushboolean(L, st->rcvd.eof);
	lua_setfield(L, -2, "eof");
	lua_pushinteger(L, st->rcvd.time);
	lua_setfield(L, -2, "time");
	lua_setfield(L, -2, "rcvd");

	return 1;
} /* lso_stat() */


static void lso_destroy(lua_State *L, struct luasocket *S) {
	cqs_unref(L, &S->onerror);

	if (S->tls.config.context) {
		SSL_CTX_free(S->tls.config.context);
		S->tls.config.context = NULL;
	}

	fifo_reset(&S->ibuf.fifo);
	fifo_reset(&S->obuf.fifo);

	/* Hack for Lua 5.1 and LuaJIT */
	if (!S->mainthread) {
		S->mainthread = L;
		so_close(S->socket);
		S->mainthread = 0;
	} else {
		so_close(S->socket);
	}

	S->socket = 0;
} /* lso_destroy() */


static lso_nargs_t lso_close(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	lso_destroy(L, S);

	return 0;
} /* lso_close() */


static lso_nargs_t lso__gc(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	S->mainthread = NULL; // disable poll cancellation
	lso_destroy(L, S);

	return 0;
} /* lso__gc() */


static int lso_type(lua_State *L) {
	struct luasocket *S;

	if ((S = lso_testself(L, 1))) {
		lua_pushstring(L, (S->socket)? "socket" : "closed socket");
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* lso_type() */


static int lso_interpose(lua_State *L) {
	return cqs_interpose(L, LSO_CLASS);
} /* lso_interpose() */


static luaL_Reg lso_methods[] = {
	{ "connect",    &lso_connect1 },
	{ "listen",     &lso_listen1 },
	{ "starttls",   &lso_starttls },
	{ "checktls",   &lso_checktls },
	{ "setvbuf",    &lso_setvbuf3 },
	{ "setmode",    &lso_setmode3 },
	{ "setbufsiz",  &lso_setbufsiz3 },
	{ "setmaxline", &lso_setmaxline3 },
	{ "settimeout", &lso_settimeout2 },
	{ "seterror",   &lso_seterror },
	{ "setmaxerrs", &lso_setmaxerrs2 },
	{ "error",      &lso_error },
	{ "clearerr",   &lso_clearerr },
	{ "onerror",    &lso_onerror2 },
	{ "recv",       &lso_recv3 },
	{ "unget",      &lso_unget2 },
	{ "send",       &lso_send5 },
	{ "flush",      &lso_flush },
	{ "uncork",     &lso_uncork },
	{ "pending",    &lso_pending },
	{ "sendfd",     &lso_sendfd3 },
	{ "recvfd",     &lso_recvfd2 },
	{ "pack",       &lso_pack4 },
	{ "unpack",     &lso_unpack2 },
	{ "fill",       &lso_fill2 },
	{ "clear",      &lso_clear },
	{ "pollfd",     &lso_pollfd },
	{ "events",     &lso_events },
	{ "timeout",    &lso_timeout },
	{ "shutdown",   &lso_shutdown },
	{ "eof",        &lso_eof },
	{ "accept",     &lso_accept },
	{ "peername",   &lso_peername },
	{ "peereid",    &lso_peereid },
	{ "peerpid",    &lso_peerpid },
	{ "localname",  &lso_localname },
	{ "stat",       &lso_stat },
	{ "close",      &lso_close },
	{ 0, 0 }
}; /* lso_methods[] */


static luaL_Reg lso_metamethods[] = {
	{ "__gc", &lso__gc },
	{ 0, 0 }
}; /* lso_metamethods[] */


static luaL_Reg lso_globals[] = {
	{ "connect",    &lso_connect2 },
	{ "listen",     &lso_listen2 },
	{ "dup",        &lso_dup },
	{ "fdopen",     &lso_fdopen },
	{ "pair",       &lso_pair },
	{ "type",       &lso_type },
	{ "interpose",  &lso_interpose },
	{ "setvbuf",    &lso_setvbuf2 },
	{ "setmode",    &lso_setmode2 },
	{ "setbufsiz",  &lso_setbufsiz2 },
	{ "setmaxline", &lso_setmaxline2 },
	{ "settimeout", &lso_settimeout1 },
	{ "setmaxerrs", &lso_setmaxerrs1 },
	{ "onerror",    &lso_onerror1 },
	{ 0, 0 }
}; /* lso_globals[] */


lso_nargs_t luaopen__cqueues_socket(lua_State *L) {
	static const struct cqs_macro macros[] = {
		{ "AF_UNSPEC",      AF_UNSPEC },
		{ "AF_INET",        AF_INET },
		{ "AF_INET6",       AF_INET6 },
		{ "AF_UNIX",        AF_UNIX },
		{ "SOCK_STREAM",    SOCK_STREAM },
		{ "SOCK_SEQPACKET", SOCK_SEQPACKET },
		{ "SOCK_DGRAM",     SOCK_DGRAM },
	};

	cqs_pushnils(L, LSO_UPVALUES); /* initial upvalues */
	cqs_newmetatable(L, LSO_CLASS, lso_methods, lso_metamethods, LSO_UPVALUES);
	lua_pushvalue(L, -1); /* push self as replacement upvalue */
	cqs_setmetaupvalue(L, -2, LSO_INDEX); /* insert self as upvalue */

	luaL_newlibtable(L, lso_globals);
	cqs_pushnils(L, LSO_UPVALUES); /* initial upvalues */
	luaL_setfuncs(L, lso_globals, LSO_UPVALUES);
	lua_pushvalue(L, -2); /* push metatable */
	cqs_setfuncsupvalue(L, -2, LSO_INDEX);

	cqs_setmacros(L, -1, macros, countof(macros), 0);

	return 1;
} /* luaopen__cqueues_socket() */


/*
 * D E B U G  &  U N I T  T E S T I N G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static size_t dbg_checksize(lua_State *L, int index) {
	lua_Number n = luaL_checknumber(L, index);

	return (n < 0)? (size_t)0 - (size_t)-n : (size_t)n;
} /* dbg_checksize() */


static size_t dbg_checkbool(lua_State *L, int index) {
	luaL_checktype(L, index, LUA_TBOOLEAN);

	return lua_toboolean(L, index);
} /* dbg_checkbool() */


static struct iovec dbg_checkstring(lua_State *L, int index) {
	struct iovec iov;

	iov.iov_base = (void *)luaL_checklstring(L, index, &iov.iov_len);

	return iov;
} /* dbg_checkstring() */


static int dbg_iov_eoh(lua_State *L) {
	struct iovec iov = dbg_checkstring(L, 1);
	_Bool eof = dbg_checkbool(L, 2);
	size_t eoh;
	int error;

	if ((size_t)-1 == (eoh = iov_eoh(&iov, eof, 0, &error))) {
		lua_pushnil(L);
		lua_pushstring(L, cqs_strerror(error));
		lua_pushinteger(L, error);

		return 3;
	} else {
		lua_pushinteger(L, eoh);

		return 1;
	}
} /* dbg_iov_eoh() */


static int dbg_iov_eob(lua_State *L) {
	struct iovec haystack = dbg_checkstring(L, 1);
	struct iovec needle = dbg_checkstring(L, 2);

	lua_pushinteger(L, iov_eob(&haystack, needle.iov_base, needle.iov_len));

	return 1;
} /* dbg_iov_eob() */


static int dbg_iov_eot(lua_State *L) {
	struct iovec iov = dbg_checkstring(L, 1);
	size_t minbuf = dbg_checksize(L, 2);
	size_t maxbuf = dbg_checksize(L, 3);
	_Bool eof = dbg_checkbool(L, 4);
	size_t n;
	int error;

	if ((size_t)-1 == (n = iov_eot(&iov, minbuf, maxbuf, eof, &error))) {
		lua_pushnil(L);
		lua_pushstring(L, cqs_strerror(error));
		lua_pushinteger(L, error);

		return 3;
	} else {
		lua_pushinteger(L, n);

		return 1;
	}
} /* dbg_iov_eot() */


static int dbg_iov_trimcr(lua_State *L) {
	struct iovec src = dbg_checkstring(L, 1);
	_Bool chomp = dbg_checkbool(L, 2);
	struct iovec dst = { memcpy(lua_newuserdata(L, src.iov_len), src.iov_base, src.iov_len), src.iov_len };

	iov_trimcr(&dst, chomp);

	lua_pushlstring(L, dst.iov_base, dst.iov_len);

	return 1;
} /* dbg_iov_trimcr() */


static int dbg_iov_trimcrlf(lua_State *L) {
	struct iovec src = dbg_checkstring(L, 1);
	_Bool chomp = dbg_checkbool(L, 2);
	struct iovec dst = { memcpy(lua_newuserdata(L, src.iov_len), src.iov_base, src.iov_len), src.iov_len };

	iov_trimcrlf(&dst, chomp);

	lua_pushlstring(L, dst.iov_base, dst.iov_len);

	return 1;
} /* dbg_iov_trimcrlf() */


static luaL_Reg dbg_globals[] = {
	{ "iov_eoh",      &dbg_iov_eoh },
	{ "iov_eob",      &dbg_iov_eob },
	{ "iov_eot",      &dbg_iov_eot },
	{ "iov_trimcr",   &dbg_iov_trimcr },
	{ "iov_trimcrlf", &dbg_iov_trimcrlf },
	{ NULL,           NULL }
}; /* dbg_globals[] */


lso_nargs_t luaopen__cqueues_socket_debug(lua_State *L) {
	luaL_newlib(L, dbg_globals);

	return 1;
} /* luaopen__cqueues_socket_debug() */


