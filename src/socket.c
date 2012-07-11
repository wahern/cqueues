#include <stddef.h>	/* NULL offsetof size_t */
#include <string.h>	/* memset(3) memchr(3) */

#include <errno.h>	/* EAGAIN EPIPE */

#include <lua.h>
#include <lauxlib.h>

#include "lib/socket.h"
#include "lib/fifo.h"
#include "lib/dns.h"


#if !defined(SAY)
#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#endif


#define lso_error_t int
#define lso_nargs_t int

#define LSO_CLASS   "Socket"
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
	} ibuf;

	struct {
		int mode;
		size_t maxline;
		size_t bufsiz;

		struct fifo fifo;

		_Bool eof;
		size_t eol;
	} obuf;

	struct socket *socket;

	int error;
}; /* struct luasocket */


static struct luasocket lso_initializer = {
	.ibuf = { .mode = LSO_RDMASK(LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ },
	.obuf = { .mode = LSO_WRMASK(LSO_INITMODE), .maxline = LSO_MAXLINE, .bufsiz = LSO_BUFSIZ },
};


static size_t lso_optsize(struct lua_State *L, int index, size_t def) {
	size_t size = luaL_optunsigned(L, index, def);

	return (size)? size : def;
} /* lso_optsize() */


static size_t lso_checksize(struct lua_State *L, int index) {
	return luaL_checkunsigned(L, index);
} /* lso_checksize() */


static int iov_chr(struct iovec *iov, size_t p) {
	return (p < iov->iov_len)? ((unsigned char *)iov->iov_base)[p] : -1;
} /* iov_chr() */


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


static void lso_pushmode(lua_State *L, int mode) {
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
} /* lso_pushmode() */


//static lso_nargs_t lso_throw(lua_State *L, struct luasocket *S, int error) {
//	return luaL_error(L, "socket: %s", so_strerror(error));
//} /* lso_throw() */


static struct luasocket *lso_newsocket(lua_State *L) {
	struct luasocket *S;

	S = lua_newuserdata(L, sizeof *S);
	*S = lso_initializer;

	fifo_init(&S->ibuf.fifo);
	fifo_init(&S->obuf.fifo);

	luaL_getmetatable(L, LSO_CLASS);
	lua_setmetatable(L, -2);

	return S;
} /* lso_newsocket() */


static lso_error_t lso_prepsocket(struct luasocket *S) {
	int error;

	if ((error = fifo_realloc(&S->ibuf.fifo, S->ibuf.bufsiz)))
		return error;

	if ((error = fifo_realloc(&S->obuf.fifo, S->obuf.bufsiz)))
		return error;

	return 0;
} /* lso_prepsocket() */


static lso_nargs_t lso_connect2(lua_State *L) {
	struct luasocket *S;
	const char *host, *port;
	int error;

	host = luaL_checkstring(L, 1);
	port = luaL_checkstring(L, 2);

	S = lso_newsocket(L);

	if (!(S->socket = so_open(host, port, DNS_T_A, PF_INET, SOCK_STREAM, so_opts(), &error)))
		goto error;

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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
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
	struct luasocket *S;
	const char *host, *port;
	int error;

	host = luaL_checkstring(L, 1);
	port = luaL_checkstring(L, 2);

	S = lso_newsocket(L);

	if (!(S->socket = so_open(host, port, DNS_T_A, PF_INET, SOCK_STREAM, so_opts(), &error)))
		goto error;

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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
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


static lso_nargs_t lso_fdopen(lua_State *L) {
	struct luasocket *S;
	int fd, error;

	fd = luaL_checkint(L, 1);

	S = lso_newsocket(L);

	if (!(S->socket = so_fdopen(fd, so_opts(), &error)))
		goto error;

	if ((error = lso_prepsocket(S)))
		goto error;

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_fdopen() */


static lso_nargs_t lso_setvbuf(struct lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	switch (luaL_checkoption(L, 2, "line", (const char *[]){ "line", "full", "nobuf", NULL })) {
	case 0:
		S->obuf.mode = LSO_LINEBUF | (S->obuf.mode & ~LSO_ALLBUF);
		break;
	case 1:
		S->obuf.mode = LSO_FULLBUF | (S->obuf.mode & ~LSO_ALLBUF);
		break;
	case 2:
		S->obuf.mode = LSO_NOBUF | (S->obuf.mode & ~LSO_ALLBUF);
		break;
	} /* switch() */

	if (S->obuf.mode & (LSO_LINEBUF|LSO_FULLBUF))
		S->obuf.bufsiz = lso_optsize(L, 3, LSO_BUFSIZ);

	return 0;
} /* lso_setvbuf() */


static lso_nargs_t lso_setmode(struct lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	lua_settop(L, 3);

	lso_pushmode(L, S->ibuf.mode);
	lso_pushmode(L, S->obuf.mode);

	if (!lua_isnil(L, 2))
		S->ibuf.mode = LSO_RDMASK(lso_imode(luaL_checkstring(L, 2), LSO_INITMODE));

	if (!lua_isnil(L, 3))
		S->obuf.mode = LSO_WRMASK(lso_imode(luaL_checkstring(L, 3), LSO_INITMODE));

	return 2;
} /* lso_setmode() */


static lso_error_t lso_fill(struct luasocket *S, size_t limit) {
	struct iovec iov;
	size_t count;
	int error;

	while (fifo_rlen(&S->ibuf.fifo) < limit) {
		if ((error = fifo_grow(&S->ibuf.fifo, 1)))
			return error;

		while (fifo_wvec(&S->ibuf.fifo, &iov, 0)) {
			if ((count = so_read(S->socket, iov.iov_base, iov.iov_len, &error))) {
				fifo_update(&S->ibuf.fifo, count);
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


static lso_error_t lso_asserterror(int error) {
	return (error)? error : EFAULT;
} /* lso_asserterror() */


static lso_error_t lso_getline(struct luasocket *S, struct iovec *iov) {
	int error;

	while (!fifo_lvec(&S->ibuf.fifo, iov)) {
		error = lso_fill(S, S->ibuf.maxline);

		if (fifo_lvec(&S->ibuf.fifo, iov))
			break;

		if (fifo_rlen(&S->ibuf.fifo) > 0 && (S->ibuf.eof || fifo_rlen(&S->ibuf.fifo) >= S->ibuf.maxline)) {
			fifo_slice(&S->ibuf.fifo, iov, 0, S->ibuf.maxline);

			break;
		}

		return lso_asserterror(error);
	}

	iov->iov_len = MIN(iov->iov_len, S->ibuf.maxline);

	return 0;
} /* lso_getline() */


static lso_error_t lso_getblock(struct luasocket *S, struct iovec *iov, size_t min, size_t max) {
	int error;

	error = lso_fill(S, max);

	if (fifo_slice(&S->ibuf.fifo, iov, 0, max) >= min)
		return 0;

	if (S->ibuf.eof && iov->iov_len > 0)
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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
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
		return luaL_argerror(L, op.index, "*a not implemented yet");
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

		return 1;
	case LSO_LINE:
		if ((error = lso_getline(S, &iov)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		return 1;
	case LSO_BLOCK:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			return 1;
		}

		if ((error = lso_getblock(S, &iov, op.size, op.size)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		return 1;
	case LSO_LIMIT:
		if (op.size == 0) {
			lua_pushlstring(L, "", 0);

			return 1;
		}

		if ((error = lso_getblock(S, &iov, 1, op.size)))
			goto error;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf.fifo, iov.iov_len);

		return 1;
	} /* switch(op) */

	error = EFAULT;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_recv3() */


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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	const unsigned char *src, *lf;
	size_t tp, p, pe, end, n;
	int mode, error;

	lua_settop(L, 5);

	src = (const void *)luaL_checklstring(L, 2, &end);
	tp = lso_checksize(L, 3) - 1;
	pe = lso_checksize(L, 4);
	mode = lso_imode(luaL_optstring(L, 5, ""), S->obuf.mode);

	luaL_argcheck(L, tp <= end, 3, "start index beyond object boundary");
	luaL_argcheck(L, pe <= end, 4, "end index beyond object boundary");

	p = tp;

	so_clear(S->socket);

	while (p < pe) {
		if (mode & (LSO_TEXT|LSO_LINEBUF)) {
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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
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


static lso_nargs_t lso_clear(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	so_clear(S->socket);

	lua_pushboolean(L, 1);

	return 1;
} /* lso_clear() */


static lso_nargs_t lso_pollfd(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	lua_pushinteger(L, so_pollfd(S->socket));

	return 1;
} /* lso_pollfd() */


static lso_nargs_t lso_events(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	short events = so_events(S->socket);
	char mode[3], *p = mode;

	if ((events & POLLIN))
		*p++ = 'r';

	if ((events & POLLOUT))
		*p++ = 'w';

	lua_pushlstring(L, mode, p - mode);

	return 1;
} /* lso_events() */


static lso_nargs_t lso_shutdown(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
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
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	lua_pushboolean(L, S->ibuf.eof);
	lua_pushboolean(L, S->obuf.eof);

	return 2;
} /* lso_eof() */


static lso_nargs_t lso_accept(lua_State *L) {
	struct luasocket *A = luaL_checkudata(L, 1, LSO_CLASS);
	struct luasocket *S;
	int fd, error;

	so_clear(A->socket);

	if (-1 == (fd = so_accept(A->socket, 0, 0, &error)))
		goto error;

	S = lso_newsocket(L);

	if (!(S->socket = so_fdopen(fd, so_opts(), &error)))
		goto error;

	if ((error = lso_prepsocket(S)))
		goto error;

	return 1;
error:
	lua_pushnil(L);
	lua_pushinteger(L, error);

	return 2;
} /* lso_accept() */


static lso_nargs_t lso__gc(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	fifo_reset(&S->ibuf.fifo);
	fifo_reset(&S->obuf.fifo);

	so_close(S->socket);
	S->socket = 0;

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
	{ "connect",  &lso_connect1 },
	{ "listen",   &lso_listen1 },
	{ "setvbuf",  &lso_setvbuf },
	{ "setmode",  &lso_setmode },
	{ "recv",     &lso_recv3 },
	{ "send",     &lso_send5 },
	{ "flush",    &lso_flush },
	{ "clear",    &lso_clear },
	{ "pollfd",   &lso_pollfd },
	{ "events",   &lso_events },
	{ "shutdown", &lso_shutdown },
	{ "eof",      &lso_eof },
	{ "accept",   &lso_accept },
	{ 0, 0 }
}; /* lso_methods[] */


static luaL_Reg lso_metamethods[] = {
	{ "__gc", &lso__gc },
	{ 0, 0 }
}; /* lso_metamethods[] */


static luaL_Reg lso_globals[] = {
	{ "connect",   &lso_connect2 },
	{ "listen",    &lso_listen2 },
	{ "fdopen",    &lso_fdopen },
	{ "interpose", &lso_interpose },
	{ 0, 0 }
}; /* lso_globals[] */


lso_nargs_t luaopen_cqueues_socket_core(lua_State *L) {
	if (luaL_newmetatable(L, LSO_CLASS)) {
		luaL_setfuncs(L, lso_metamethods, 0);

		lua_newtable(L);
		luaL_setfuncs(L, lso_methods, 0);
		lua_setfield(L, -2, "__index");
	}

	lua_pop(L, 1);

	lua_newtable(L);
	luaL_setfuncs(L, lso_globals, 0);

	return 1;
} /* luaopen_cqueues_socket_core() */

