/* ==========================================================================
 * socket.c - Lua Continuation Queues
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
#include <stddef.h>	/* NULL offsetof size_t */
#include <stdarg.h>	/* va_list va_start va_arg va_end */
#include <stdlib.h>	/* abs(3) strtol(3) */
#include <string.h>	/* memset(3) memchr(3) memcpy(3) */

#include <math.h>	/* NAN */

#include <errno.h>	/* EAGAIN EPIPE EINTR */

#include <sys/types.h>
#include <sys/socket.h>	/* AF_UNIX SOCK_STREAM SOCK_DGRAM PF_UNSPEC socketpair(2) */
#include <sys/un.h>	/* struct sockaddr_un */

#include <unistd.h>	/* dup(2) close(2) */

#include <arpa/inet.h>	/* ntohs(3) */

#include <openssl/crypto.h> /* CRYPTO_LOCK_SSL CRYPTO_add() */

#include <lua.h>
#include <lauxlib.h>

#include "lib/socket.h"
#include "lib/fifo.h"
#include "lib/dns.h"

#include "cqueues.h"


/*
 * L U A  S O C K E T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define lso_error_t int
#define lso_nargs_t int

#define LSO_CLASS   "CQS Socket"
#define LSO_BUFSIZ  4096
#define LSO_MAXLINE 4096

#define LSO_LINEBUF 0x01
#define LSO_FULLBUF 0x02
#define LSO_NOBUF   0x04
#define LSO_ALLBUF  (LSO_LINEBUF|LSO_FULLBUF|LSO_NOBUF)
#define LSO_TEXT    0x08
#define LSO_BINARY  0x10

#define LSO_INITMODE (LSO_LINEBUF|LSO_TEXT)
#define LSO_RDMASK(m) ((m) & ~LSO_ALLBUF)
#define LSO_WRMASK(m) (m)


/*
 * A placeholder until we make it optional. Some Microsoft services have
 * buggy line buffering and will choke if, e.g., an SMTP command is
 * fragmented across TCP packets.
 */
#define LSO_DEFRAG 1


struct luasocket {
	struct {
		int mode;
		size_t maxline;
		size_t bufsiz;

		struct fifo fifo;

		_Bool eof;
		_Bool eom;
	} ibuf;

	struct {
		int mode;
		size_t maxline;
		size_t bufsiz;

		struct fifo fifo;

		_Bool eof;
		size_t eol;
	} obuf;

	int family;
	int type;
	struct socket *socket;

	cqs_ref_t onerror;

	lua_State *mainthread;

	int error;
}; /* struct luasocket */


static struct luasocket lso_initializer = {
	.ibuf = { .mode = LSO_RDMASK(LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ },
	.obuf = { .mode = LSO_WRMASK(LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ },
	.type = AF_UNSPEC,
	.type = SOCK_STREAM,
	.onerror = LUA_NOREF,
};


static size_t lso_optsize(struct lua_State *L, int index, size_t def) {
	size_t size = luaL_optunsigned(L, index, def);

	return (size)? size : def;
} /* lso_optsize() */


static size_t lso_checksize(struct lua_State *L, int index) {
	return luaL_checkunsigned(L, index);
} /* lso_checksize() */


static int lso_tofileno(lua_State *L, int index) {
	struct luasocket *so;
	luaL_Stream *fh;
	int fd;

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

	/* TODO: Parse .sa_bind */

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

	if (lso_altfield(L, index, "nodelay", "sin_nodelay"))
		opts.sin_nodelay = lso_popbool(L);

	if (lso_altfield(L, index, "nopush", "sin_nopush"))
		opts.sin_nopush = lso_popbool(L);

	if (lso_altfield(L, index, "nonblock", "fd_nonblock"))
		opts.fd_nonblock = lso_popbool(L);

	if (lso_altfield(L, index, "cloexec", "fd_cloexec"))
		opts.fd_cloexec = lso_popbool(L);

	if (lso_altfield(L, index, "nosigpipe", "fd_nosigpipe"))
		opts.fd_nosigpipe = lso_popbool(L);

	if (lso_altfield(L, index, "verify", "tls_verify"))
		opts.tls_verify = lso_popbool(L);

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


static struct luasocket *lso_checkvalid(lua_State *L, int index, struct luasocket *S) {
	luaL_argcheck(L, !!S->socket, index, "socket closed");
	return S;
} /* lso_checkvalid() */


static struct luasocket *lso_checkself(lua_State *L, int index) {
	return lso_checkvalid(L, index, luaL_checkudata(L, index, LSO_CLASS));
} /* lso_checkself() */


static int iov_chr(struct iovec *iov, size_t p) {
	return (p < iov->iov_len)? ((unsigned char *)iov->iov_base)[p] : -1;
} /* iov_chr() */


static size_t iov_eoh(struct iovec *iov, _Bool eof) {
	unsigned char *p, *pe;
	
	p = iov->iov_base;
	pe = p + iov->iov_len;

	while (p < pe && (p = memchr(p, '\n', pe - p))) {
		if (++p < pe && *p != ' ' && *p != '\t')
			return p - (unsigned char *)iov->iov_base;
	}

	if (eof)
		return iov->iov_len;

	return 0;
} /* iov_eoh() */


/* strip cr from crlf sequences */
static size_t iov_trimcr(struct iovec *iov) {
	unsigned char *p, *pe;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	while (p < pe && (p = memchr(p, '\r', pe - p))) {
		if (++p >= pe) {
			--pe;
			break;
		} else if (*p == '\n') {
			memmove(p - 1, p, pe - p);
			--pe;
		}
	}

	return iov->iov_len = pe - (unsigned char *)iov->iov_base;
} /* iov_trimcr() */


/* strip cr?lf from cr?lf sequences */
static size_t iov_trimcrlf(struct iovec *iov) {
	unsigned char *sp, *p, *pe;

	sp = iov->iov_base;
	p = iov->iov_base;
	pe = p + iov->iov_len;

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

	return iov->iov_len = pe - (unsigned char *)iov->iov_base;
} /* iov_trimcrlf() */


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
		} /* switch() */
	} /* while() */

	return mode;
} /* lso_imode() */


static void lso_pushmode(lua_State *L, int mode, _Bool libc) {
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
		char flag[8];

		if (mode & LSO_TEXT)
			flag[0] = 't';
		else if (mode & LSO_BINARY)
			flag[0] = 'b';
		else
			flag[0] = '-';

		if (mode & LSO_NOBUF)
			flag[1] = 'n';
		else if (mode & LSO_LINEBUF)
			flag[1] = 'l';
		else if (mode & LSO_FULLBUF)
			flag[1] = 'f';
		else
			flag[1] = '-';

		lua_pushlstring(L, flag, 2);
	}
} /* lso_pushmode() */


//static lso_nargs_t lso_throw(lua_State *L, struct luasocket *S, int error) {
//	return luaL_error(L, "socket: %s", so_strerror(error));
//} /* lso_throw() */


static struct luasocket *lso_prototype(lua_State *L) {
	static const int regindex;
	struct luasocket *P;

	lua_rawgetp(L, LUA_REGISTRYINDEX, &regindex);

	P = lua_touserdata(L, -1);

	lua_pop(L, 1);

	if (P)
		return P;

	P = lua_newuserdata(L, sizeof *P);
	*P = lso_initializer;
	lua_rawsetp(L, LUA_REGISTRYINDEX, &regindex);

	return P;
} /* lso_prototype() */


static struct luasocket *lso_newsocket(lua_State *L, int family, int type) {
	struct luasocket *S;

	S = lua_newuserdata(L, sizeof *S);
	*S = *lso_prototype(L);

	S->family = family;
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


static lso_error_t lso_adjbufs(struct luasocket *S) {
	int error;

	if ((error = fifo_realloc(&S->ibuf.fifo, S->ibuf.bufsiz)))
		return error;

	if ((error = fifo_realloc(&S->obuf.fifo, S->obuf.bufsiz)))
		return error;

	return 0;
} /* lso_adjbufs() */


static lso_error_t lso_prepsocket(struct luasocket *S) {
	return lso_adjbufs(S);
} /* lso_prepsocket() */


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
		family = luaL_optinteger(L, -1, AF_INET);
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
		family = luaL_optinteger(L, 3, AF_INET);
		type = luaL_optinteger(L, 4, SOCK_STREAM);
	}

	S = lso_newsocket(L, family, type);

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
		if (!(S->socket = so_open(host, port, DNS_T_A, family, type, &opts, &error)))
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
		lua_pushboolean(L, 1);

		return 1;
	} else {
		lua_pushboolean(L, 0);
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
		family = luaL_optinteger(L, -1, AF_INET);
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
		family = luaL_optinteger(L, 3, AF_INET);
		type = luaL_optinteger(L, 4, SOCK_STREAM);
	}

	S = lso_newsocket(L, family, type);

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
		if (!(S->socket = so_open(host, port, DNS_T_A, family, type, &opts, &error)))
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
		lua_pushboolean(L, 1);

		return 1;
	} else {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}
} /* lso_listen1() */


static lso_nargs_t lso_starttls(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	SSL_CTX **ctx = luaL_testudata(L, 2, "SSL_CTX*");
	int error;

	so_clear(S->socket);

	if (!(error = so_starttls(S->socket, (ctx)? *ctx : 0))) {
		lua_pushboolean(L, 1);

		return 1;
	} else {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 2;
	}
} /* lso_starttls() */


static lso_nargs_t lso_checktls(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	SSL **ssl;
	int error;

	ssl = lua_newuserdata(L, sizeof *ssl);

	if (!(*ssl = so_checktls(S->socket)))
		return 0;

	luaL_getmetatable(L, "SSL*");

	if (lua_isnil(L, -1))
		return 0;

	lua_setmetatable(L, -2);

	CRYPTO_add(&(*ssl)->references, 1, CRYPTO_LOCK_SSL);

	return 1;
} /* lso_checktls() */


lso_error_t cqs_socket_fdopen(lua_State *L, int fd, const struct so_options *_opts) {
	struct so_options opts = *((_opts)? _opts : so_opts());
	struct sockaddr_storage ss;
	struct luasocket *S;
	int family = AF_UNSPEC, type = SOCK_STREAM, error;

	if (0 == getsockname(fd, (struct sockaddr *)&ss, &(socklen_t){ sizeof ss })) {
		family = ss.ss_family;

		if (0 != getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &(socklen_t){ sizeof type }))
			goto syerr;
	} else {
		switch (errno) {
		case ENOTSOCK:
		case EOPNOTSUPP:
			break;
		default:
			goto syerr;
		}
	}

	S = lso_newsocket(L, family, type);

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


static lso_nargs_t lso_fdopen(lua_State *L) {
	struct so_options opts;
	struct luasocket *S;
	int ofd, fd = -1, error;

	if (lua_istable(L, 1)) {
		opts = lso_checkopts(L, 1);

		if (lso_altfield(L, 1, "fd", "file", "socket")) {
			ofd = lso_tofileno(L, -1);
		} else {
			lua_rawgeti(L, 1, 1);
			ofd = luaL_checkint(L, -1);
		}

		lua_pop(L, 1);
	} else {
		opts = *so_opts();
		ofd = lso_tofileno(L, 1);
	}

	if (ofd < 0)
		goto badfd;

	if (-1 == (fd = dup(ofd)))
		goto syerr;

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
} /* lso_fdopen() */


static lso_nargs_t lso_pair(lua_State *L) {
	struct luasocket *a = NULL, *b = NULL;
	struct so_options *opts = so_opts();
	int fd[2] = { -1, -1 };
	int type, error;

	type = luaL_optinteger(L, 1, SOCK_STREAM);

	a = lso_newsocket(L, AF_UNIX, type);
	b = lso_newsocket(L, AF_UNIX, type);

	if (0 != socketpair(AF_UNIX, type, PF_UNSPEC, fd))
		goto syerr;

	opts->fd_close.arg = a;
	opts->fd_close.cb = &lso_closefd;

	if (!(a->socket = so_fdopen(fd[0], opts, &error)))
		goto error;

	fd[0] = -1;

	if ((error = lso_prepsocket(a)))
		goto error;

	opts->fd_close.arg = b;
	opts->fd_close.cb = &lso_closefd;

	if (!(b->socket = so_fdopen(fd[1], opts, &error)))
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
	switch (luaL_checkoption(L, index, "line", (const char *[]){ "line", "full", "nobuf", NULL })) {
	case 0:
		return LSO_LINEBUF;
	case 1:
		return LSO_FULLBUF;
	case 2:
	default:
		return LSO_NOBUF;
	}
} /* lso_checkvbuf() */


static lso_nargs_t lso_setvbuf_(struct lua_State *L, struct luasocket *S, int modeidx, int bufidx) {
	lso_pushmode(L, S->obuf.mode, 1);
	lua_pushnumber(L, S->obuf.bufsiz);

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
	lso_pushmode(L, S->ibuf.mode, 0);
	lso_pushmode(L, S->obuf.mode, 0);

	if (!lua_isnil(L, ridx))
		S->ibuf.mode = LSO_RDMASK(lso_imode(luaL_checkstring(L, ridx), LSO_INITMODE));

	if (!lua_isnil(L, widx))
		S->obuf.mode = LSO_WRMASK(lso_imode(luaL_checkstring(L, widx), LSO_INITMODE));

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
	lua_pushnumber(L, S->ibuf.bufsiz);
	lua_pushnumber(L, S->obuf.bufsiz);

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
	lua_pushnumber(L, S->ibuf.maxline);
	lua_pushnumber(L, S->obuf.maxline);

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


static lso_error_t lso_fill(struct luasocket *S, size_t limit) {
	struct iovec iov;
	size_t prepbuf, count;
	int error;

	if (S->ibuf.eom && fifo_rlen(&S->ibuf.fifo) > 0)
		return 0;

	prepbuf = (S->type == SOCK_DGRAM)? (SO_MIN(limit, 65536)) : 1;

	while (fifo_rlen(&S->ibuf.fifo) < limit) {
		if ((error = fifo_grow(&S->ibuf.fifo, prepbuf)))
			return error;

		while (fifo_wvec(&S->ibuf.fifo, &iov, 0)) {
			if ((count = so_read(S->socket, iov.iov_base, iov.iov_len, &error))) {
				fifo_update(&S->ibuf.fifo, count);

				if (S->type == SOCK_DGRAM) {
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


static inline _Bool lso_isblank(unsigned char ch) {
	return ch == ' ' && ch == '\t';
} /* lso_isblank() */

static inline _Bool lso_isfname(unsigned char ch) {
	return ch >= 33 && ch <= 126 && ch != ':';
} /* lso_isfname() */

static inline _Bool lso_isbreak(struct iovec *iov, _Bool eof) {
	unsigned char *p, *pe;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	while (p < pe && lso_isfname(*p))
		p++;

	while (p < pe && lso_isblank(*p))
		p++;

	if (p < pe && *p == ':')
		return 0;

	return eof || !!memchr(p, '\n', pe - p);
} /* lso_isbreak() */

static lso_error_t lso_getheader(struct luasocket *S, struct iovec *iov) {
	unsigned char *p, *pe;
	size_t eoh;
	_Bool eof;
	int error;

	fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

	if (lso_isbreak(iov, lso_nomore(S, S->ibuf.maxline)))
		goto nomore;

	if (!(eoh = iov_eoh(iov, lso_nomore(S, S->ibuf.maxline)))) {
		error = lso_fill(S, S->ibuf.maxline);

		fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

		if (lso_isbreak(iov, lso_nomore(S, S->ibuf.maxline)))
			goto nomore;

		if (!(eoh = iov_eoh(iov, lso_nomore(S, S->ibuf.maxline))))
			return lso_asserterror(error);
	}

	iov->iov_len = eoh;

	p = iov->iov_base;
	pe = p + iov->iov_len;

	while (p < pe && lso_isfname(*p))
		p++;

	while (p < pe && lso_isblank(*p))
		p++;

	return (p < pe && *p == ':')? 0 : EPIPE;
nomore:
	iov->iov_len = 0;

	return 0;
} /* lso_getheader() */


static lso_error_t lso_getblock(struct luasocket *S, struct iovec *iov, size_t min, size_t max) {
	int error;

	error = lso_fill(S, max);

	if (fifo_slice(&S->ibuf.fifo, iov, 0, max) >= min)
		return 0;

	if ((S->ibuf.eof || S->ibuf.eom) && iov->iov_len > 0)
		return 0;

	return lso_asserterror(error);
} /* lso_getblock() */


struct lso_rcvop {
	int index;

	enum {
		LSO_NUMBER,
		LSO_SLURP,
		LSO_CHOMP,
		LSO_LINE,
		LSO_FIELD,
		LSO_HEADER,
		LSO_BLOCK,
		LSO_LIMIT,
	} type;

	size_t size;
	int mode;
}; /* struct lso_rcvop */


static struct lso_rcvop lso_checkrcvop(lua_State *L, int index, int mode) {
	struct lso_rcvop op = { index, LSO_CHOMP, 0, mode };
	lua_Number size;

	if (!lua_isnumber(L, index)) {
		op.type = luaL_checkoption(L, index, "*l", (const char *[]){
			[LSO_NUMBER] = "*n",
			[LSO_SLURP]  = "*a",
			[LSO_CHOMP]  = "*l", 
			[LSO_LINE]   = "*L",
			[LSO_FIELD]  = "*h",
			[LSO_HEADER] = "*H",
			NULL
		});
	} else {
		if ((size = luaL_checknumber(L, index)) < 0) {
			op.type = LSO_LIMIT;
			op.size = -size;
		} else {
			op.type   = LSO_BLOCK;
			op.size = size;
		}
	}

	return op;
} /* lso_checkrcvop() */


static lso_nargs_t lso_recv3(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	struct lso_rcvop op;
	struct iovec iov;
	size_t count;
	int error;

	lua_settop(L, 3);

	op = lso_checkrcvop(L, 2, lso_imode(luaL_optstring(L, 3, ""), S->ibuf.mode));

	so_clear(S->socket);

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
				iov_trimcr(&iov);

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

		if (iov_chr(&iov, count - 1) == '\n') {
			count--;

			if ((op.mode & LSO_TEXT) && count > 0) {
				if (iov_chr(&iov, count - 1) == '\r')
					count--;
			}
		}

		lua_pushlstring(L, iov.iov_base, count);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		break;
	case LSO_LINE:
		if ((error = lso_getline(S, &iov)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		break;
	case LSO_FIELD:
		if ((error = lso_getheader(S, &iov)))
			goto error;

		if ((count = iov.iov_len)) {
			iov_trimcrlf(&iov);

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
				iov_trimcr(&iov);

			lua_pushlstring(L, iov.iov_base, iov.iov_len);
			fifo_discard(&S->ibuf.fifo, count);
		} else {
			lua_pushnil(L);
		}

		break;
	case LSO_BLOCK:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			break;
		}

		if ((error = lso_getblock(S, &iov, op.size, op.size)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		break;
	case LSO_LIMIT:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			break;
		}

		if ((error = lso_getblock(S, &iov, 1, op.size)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

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
		if (S->obuf.eol > 0)
			amount = S->obuf.eol;
		else if (fifo_rlen(&S->obuf.fifo) > S->obuf.maxline)
			amount = S->obuf.maxline;
	} else if (mode & LSO_FULLBUF) {
		if (fifo_rlen(&S->obuf.fifo) > S->obuf.bufsiz)
			amount = S->obuf.bufsiz;
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

	lua_pushnumber(L, p - tp);

	return 1;
error:
	lua_pushnumber(L, p - tp);
	lua_pushinteger(L, error);

	return 2;
} /* lso_send5() */


static lso_nargs_t lso_flush(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	int mode = lso_imode(luaL_optstring(L, 2, "n"), S->obuf.mode);
	int error;

	if ((error = lso_doflush(S, mode))) {
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
	struct luasocket *so;
	luaL_Stream *fh;
	int fd, error;

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

	if ((error = fifo_grow(&S->ibuf.fifo, bufsiz)))
		goto error;

	fifo_wvec(&S->ibuf.fifo, &iov, 1);

	msg = so_fdmsg(iov.iov_base, iov.iov_len, -1);

	so_clear(S->socket);

	if ((error = so_recvmsg(S->socket, msg, 0)))
		goto error;

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

	if ((error = cqs_socket_fdopen(L, fd, so_opts())))
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

	lua_settop(L, 2);

	count = luaL_optunsigned(L, 2, 32);

	so_clear(S->socket);

	if (fifo_rbits(&S->ibuf.fifo) < count) {
		size_t rem = ((count - fifo_rbits(&S->ibuf.fifo)) + 7U) / 8U;

		if ((error = lso_fill(S, rem))) {
			if (fifo_rbits(&S->ibuf.fifo) < count)
				goto error;
		}
	}

	value = fifo_unpack(&S->ibuf.fifo, count);

	if (value != (unsigned long long)(lua_Number)value)
		goto range;

	lua_pushnumber(L, (lua_Number)value);

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

	if ((error = lso_fill(S, size))) {
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
	return NAN;
} /* cqs_socket_timeout() */


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

	lua_pushboolean(L, S->ibuf.eof);
	lua_pushboolean(L, S->obuf.eof);

	return 2;
} /* lso_eof() */


static lso_nargs_t lso_accept(lua_State *L) {
	struct luasocket *A = luaL_checkudata(L, 1, LSO_CLASS);
	struct luasocket *S;
	struct so_options opts;
	int fd, error;

	so_clear(A->socket);

	if (-1 == (fd = so_accept(A->socket, 0, 0, &error)))
		goto error;

	if ((error = cqs_socket_fdopen(L, fd, so_opts())))
		goto error;

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_accept() */


static lso_nargs_t lso_pushname(lua_State *L, struct sockaddr_storage *ss) {
	switch (ss->ss_family) {
	case AF_INET:
		/* FALL THROUGH */
	case AF_INET6:
		lua_pushinteger(L, ss->ss_family);
		lua_pushstring(L, sa_ntoa(ss));
		lua_pushinteger(L, ntohs(*sa_port(ss)));

		return 3;
	case AF_UNIX:
		lua_pushinteger(L, ss->ss_family);
		lua_pushstring(L, sa_ntoa(ss));

		return 2;
	default:
		lua_pushinteger(L, ss->ss_family);

		return 1;
	}
} /* lso_pushname() */


static lso_nargs_t lso_peername(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	struct sockaddr_storage ss;
	int error;

	if ((error = so_remoteaddr(S->socket, &ss, &(socklen_t){ sizeof ss }))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	return lso_pushname(L, &ss);
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
	int error;

	if ((error = so_localaddr(S->socket, &ss, &(socklen_t){ sizeof ss }))) {
		lua_pushnil(L);
		lua_pushinteger(L, error);

		return 2;
	}

	return lso_pushname(L, &ss);
} /* lso_localname() */


static lso_nargs_t lso_stat(lua_State *L) {
	struct luasocket *S = lso_checkself(L, 1);
	const struct so_stat *st = so_stat(S->socket);

	lua_newtable(L);

	lua_newtable(L);
	lua_pushnumber(L, st->sent.count);
	lua_setfield(L, -2, "count");
	lua_pushboolean(L, st->sent.eof);
	lua_setfield(L, -2, "eof");
	lua_pushnumber(L, st->sent.time);
	lua_setfield(L, -2, "time");
	lua_setfield(L, -2, "sent");

	lua_newtable(L);
	lua_pushnumber(L, st->rcvd.count);
	lua_setfield(L, -2, "count");
	lua_pushboolean(L, st->rcvd.eof);
	lua_setfield(L, -2, "eof");
	lua_pushnumber(L, st->rcvd.time);
	lua_setfield(L, -2, "time");
	lua_setfield(L, -2, "rcvd");

	return 1;
} /* lso_stat() */


static void lso_destroy(lua_State *L, struct luasocket *S) {
	cqs_unref(L, &S->onerror);

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


static int lso_interpose(lua_State *L) {
	luaL_getmetatable(L, LSO_CLASS);
	lua_getfield(L, -1, "__index");
	
	lua_pushvalue(L, -4); /* push method name */
	lua_gettable(L, -2);  /* push old method */
			
	lua_pushvalue(L, -5); /* push method name */
	lua_pushvalue(L, -5); /* push new method */
	lua_settable(L, -4);  /* replace old method */

	return 1; /* return old method */
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
	{ "fdopen",     &lso_fdopen },
	{ "pair",       &lso_pair },
	{ "interpose",  &lso_interpose },
	{ "setvbuf",    &lso_setvbuf2 },
	{ "setmode",    &lso_setmode2 },
	{ "setbufsiz",  &lso_setbufsiz2 },
	{ "setmaxline", &lso_setmaxline2 },
	{ "onerror",    &lso_onerror1 },
	{ 0, 0 }
}; /* lso_globals[] */


lso_nargs_t luaopen__cqueues_socket(lua_State *L) {
	static const struct cqs_macro macros[] = {
		{ "AF_UNSPEC",   AF_UNSPEC },
		{ "AF_INET",     AF_INET },
		{ "AF_INET6",    AF_INET6 },
		{ "AF_UNIX",     AF_UNIX },
		{ "SOCK_STREAM", SOCK_STREAM },
		{ "SOCK_DGRAM",  SOCK_DGRAM },
	};

	if (luaL_newmetatable(L, LSO_CLASS)) {
		luaL_setfuncs(L, lso_metamethods, 0);

		luaL_newlib(L, lso_methods);
		lua_setfield(L, -2, "__index");
	}

	lua_pop(L, 1);

	luaL_newlib(L, lso_globals);

	cqs_addmacros(L, -1, macros, countof(macros), 0);

	return 1;
} /* luaopen__cqueues_socket() */
