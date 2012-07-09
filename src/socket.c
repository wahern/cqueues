#include <stddef.h>	/* NULL offsetof size_t */
#include <string.h>	/* memset(3) memchr(3) */

#include <errno.h>	/* EAGAIN EPIPE */

#include "lib/socket.h"
#include "lib/fifo.h"
#include "lib/dns.h"


#define NOTREACHED __builtin_unreachable()

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
#define LSO_WAITALL 0x20

#define LSO_INITMODE (LSO_FULLBUF|LSO_TEXT)
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
		struct {
			int mode;
			size_t maxline;
			size_t bufsiz;
		} ibuf;

		struct {
			int mode;
			size_t maxline;
			size_t bufsiz;
		} obuf;
	} opts;

	struct socket *socket;

	_Bool eof, fin;
	int error;

	struct fifo ibuf, obuf;
	size_t eol;
}; /* struct luasocket */


static size_t lso_optsize(struct lua_State *L, int index, size_t def) {
	size_t size = luaL_optunsigned(L, index, def);

	return (size)? size : def;
} /* lso_optsize() */


static size_t lso_checksize(struct lua_State *L, int index) {
	return luaL_checkunsigned(L, index);
} /* lso_checksize() */


static int iov_chr(struct iov *iov, size_t p) {
	return (p < iov->iov_len)? ((unsigned char *)iov->iov_base)[p] : -1;
} /* iov_chr() */


static size_t iov_okay(struct iov *iov, size_t limit, _Bool eof) {
	return (iov->iov_len >= limit)? limit : (eof)? iov->iov_len : 0;
} /* iov_okay() */


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
		case 'w':
			mode |= LSO_WAITALL;
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

	if (mode & LSO_WAITALL)
		flag[2] = 'w';
	else
		flag[2] = '-';

	lua_pushlstring(L, flag, 3);
} /* lso_pushmode() */


static lso_nargs_t lso_throw(lua_State *L, struct luasocket *S, int error) {
	return luaL_error(L, "socket: %s", so_strerror(error));
} /* lso_throw() */


static struct luasocket *lso_create(lua_State *L) {
	struct luasocket *S = 0;
	int mode = LSO_INITMODE;
	size_t bufsiz = LSO_BUFSIZ;
	size_t maxline = LSO_MAXLINE;
	const char *host;
	int port, error;

	if (lua_istable(L, 1)) {
		lua_getfield(L, 1, "host");
		host = luaL_checkstring(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, 1, "port");
		port = luaL_checkint(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, 1, "mode");
		if (!lua_isnil(L, -1))
			mode = lso_imode(luaL_checkstring(L, -1), mode);
		lua_pop(L, 1);

		lua_getfield(L, 1, "bufsiz");
		bufsiz = lso_optsize(L, -1, bufsiz);
		lua_pop(L, 1);

		lua_getfield(L, 1, "maxline");
		maxline = lso_optsize(L, -1, maxline);
		lua_pop(L, 1);
	} else {
		host = luaL_checkstring(L, 1);
		port = luaL_checkint(L, 2);
		if (!lua_isnoneornil(L, 3))
			mode = lso_imode(luaL_checkstring(L, 3), mode);
	}

	S = lua_newuserdata(L, sizeof *S);

	memset(S, 0, sizeof *S);

	fifo_init(&S->ibuf);
	fifo_init(&S->obuf);

	S->opts.ibuf.mode = LSO_RDMASK(mode);
	S->opts.ibuf.maxline = maxline;
	S->opts.ibuf.bufsiz = bufsiz;

	S->opts.obuf.mode = LSO_WRMASK(mode);
	S->opts.obuf.maxline = maxline;
	S->opts.obuf.bufsiz = bufsiz;

	luaL_getmetatable(L, LSO_CLASS);
	lua_setmetatable(L, -2);

	if ((error = fifo_realloc(&S->ibuf, S->opts.ibuf.bufsiz)))
		goto error;

	if ((error = fifo_realloc(&S->obuf, S->opts.obuf.bufsiz)))
		goto error;

	if (!(S->socket = so_open(host, port, DNS_T_A, PF_INET, SOCK_STREAM, so_opts(), &error)))
		goto error;

	return S;
error:
	return luaL_error(L, "socket: %s", so_strerror(error));
} /* lso_create() */


static lso_nargs_t lso_connect(lua_State *L) {
	struct luasocket *S = lso_create(L);

	(void)so_connect(S->socket);

	return 1;
} /* lso_connect() */


static lso_nargs_t lso_listen(lua_State *L) {
	struct luasocket *S = lso_create(L);

	(void)so_listen(S->socket);

	return 1;
} /* lso_listen() */


static lso_nargs_t lso_setvbuf(struct lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	switch (luaL_checkoption(L, 2, "line", (const char *[]){ "line", "full", "nobuf", NULL })) {
	case 0:
		S->opts.obuf.mode = LSO_LINEBUF | (S->opts.obuf.mode & ~LSO_ALLBUF);
		break;
	case 1:
		S->opts.obuf.mode = LSO_FULLBUF | (S->opts.obuf.mode & ~LSO_ALLBUF);
		break;
	case 2:
		S->opts.obuf.mode = LSO_NOBUF | (S->opts.obuf.mode & ~LSO_ALLBUF);
		break;
	} /* switch() */

	if (S->opts.obuf.mode & (LSO_LINEBUF|LSO_FULLBUF))
		S->opts.obuf.bufsiz = lso_optsize(L, 3, LSO_BUFSIZ);

	return 0;
} /* lso_setvbuf() */


static lso_nargs_t lso_setmode(struct lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	int mode;

	lua_settop(L, 3);

	lso_pushmode(L, S->opts.ibuf.mode);
	lso_pushmode(L, S->opts.obuf.mode);

	if (!lua_isnil(L, 2))
		S->opts.ibuf.mode = LSO_RDMASK(lso_imode(luaL_checkstring(L, 2), LSO_INITMODE));

	if (!lua_isnil(L, 3))
		S->opts.obuf.mode = LSO_WRMASK(lso_imode(luaL_checkstring(L, 3), LSO_INITMODE));

	return 2;
} /* lso_setmode() */


static lso_error_t lso_fill(struct luasocket *S, size_t limit) {
	struct iovec iov;
	size_t count;
	int error;

	while (fifo_rlen(&S->ibuf) < limit) {
		if ((error = fifo_grow(&S->ibuf, 1)))
			return error;

		while (fifo_wvec(&S->ibuf, &iov, 0)) {
			if ((count = so_read(S->socket, iov.iov_base, iov.iov_len, &error))) {
				fifo_update(&S->ibuf, count);
			} else {
				switch (error) {
				case EPIPE:
					S->eof = 1;
				case EAGAIN:
					return 0;
				default:
					return S->error = error;
				} /* switch() */
			}
		}
	}

	return 0;
} /* lso_fill() */


static lso_error_t lso_getline(struct luasocket *S, struct iovec *iov) {
	int error;

	while (!fifo_lvec(&S->ibuf, iov)) {
		error = lso_fill(S, S->opts.ibuf.maxline);

		if (fifo_lvec(&S->ibuf, iov))
			break;

		if (fifo_rvec(&S->ibuf, iov) && (S->eof || iov.iov_len >= S->opts.ibuf.maxline))
			break;

		iov->iov_len = 0;

		if (error)
			return error;

		break;
	}

	iov->iov_len = MIN(iov->iov_len, S->opts.ibuf.maxline);

	return 0;
} /* lso_getline() */


static lso_error_t lso_getblock(struct luasocket *S, struct iovec *iov, size_t size, _Bool eof) {
	int error;

	error = lso_fill(S, max);

	fifo_rvec(&S->ibuf, &iov);

	return ((iov.iov_len = iov_okay(&iov, size, eof)))? 0 : error;
} /* lso_getblock() */


struct lso_recv {
	int index;

	enum {
		LSO_NUMBER,
		LSO_SLURP,
		LSO_CHOMP,
		LSO_LINE,
		LSO_BLOCK,
		LSO_LIMIT,
	} op;

	size_t size;
	int mode;
}; /* struct lso_recv */


static struct lso_recv lso_checkrecv(lua_State *L, int index, int mode) {
	struct lso_recv rcv = { index, LSO_CHOMP, 0, mode };
	lua_Number size;

	if (!lua_isnumber(L, index)) {
		rcv.op = luaL_checkoption(L, index, "*l", (const char *[]){
			[LSO_NUMBER] = "*n",
			[LSO_SLURP]  = "*a",
			[LSO_CHOMP]  = "*l", 
			[LSO_LINE]   = "*L",
			NULL
		});
	} else {
		if ((size = luaL_checknumber(L, index)) < 0) {
			rcv.op   = LSO_LIMIT;
			rcv.size = -size;
		} else {
			rcv.op   = LSO_BLOCK;
			rcv.size = size;
		}
	}

	return rcv;
} /* lso_checkrecv() */


static lso_nargs_t lso_dorecv(lua_State *L, struct luasocket *S, const struct lso_recv *rcv) {
	struct iovec iov;
	size_t count;
	int error;

	so_clear(S->socket);

	switch (rcv->op) {
	case LSO_NUMBER:
		return luaL_argerror(L, rcv->index, "*n not implemented yet");
	case LSO_SLURP:
		return luaL_argerror(L, rcv->index, "*a not implemented yet");
	case LSO_CHOMP:
		if ((error = lso_getline(S, &iov)))
			goto error;
		else if (!(count = iov.iov_len))
			goto yield;

		if (iov_chr(&iov, count - 1) == '\n') {
			count--;

			if ((rcv->mode & LSO_TEXT) && count > 0) {
				if (iov_chr(&iov, count - 1) == '\r')
					count--;
			}
		}

		lua_pushlstring(L, iov.iov_base, count);
		fifo_discard(&S->ibuf, iov.iov_len);

		return 1;
	case LSO_LINE:
		if ((error = lso_getline(S, &iov)))
			goto error;
		else if (!iov.iov_len)
			goto yield;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf, iov.iov_len);

		return 1;
	case LSO_BLOCK:
		if (rcv->size == 0) {
			lua_pushlstring(L, "", 0);

			return 1;
		}

		if ((error = lso_getblock(S, &iov, rcv->size, S->eof)))
			goto error;
		else if (!iov.iov_len)
			goto yield;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf, iov.iov_len);

		return 1;
	case LSO_LIMIT:
		if (rcv->size == 0) {
			lua_pushlstring(L, "", 0);

			return 1;
		}

		if ((error = lso_getblock(S, &iov, rcv->size, 1)))
			goto error;
		else if (!iov.iov_len)
			goto yield;

		lua_pushlstring(L, iov.iov_base, iov.iov_len);
		fifo_discard(&S->ibuf, iov.iov_len);

		return 1;
	default:
		error = EFAULT;

		goto error;
	} /* switch(op) */

	NOTREACHED;
yield:
	if (S->eof || !(rcv->mode & LSO_WAITALL)) {
		lua_pushnil(L);

		return 1;
	}

	return LUA_YIELD;
error:
	return lso_throw(L, S, error);
} /* lso_dorecv() */


static lso_nargs_t lso_recv(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	struct lso_recv rcv;
	int mode, error;

	lua_settop(L, 3);

	mode = lso_imode(luaL_optstring(L, 3, ""), S->opts.ibuf.mode);

	rcv = lso_checkrecv(L, 2, mode);
	lso_dorecv(L, S, &rcv);

	return 1;
yield:
	lua_pushvalue(L, 1);

	return lua_yieldk(L, 1, 0, &lso_recv);
} /* lso_recv() */


static lso_error_t lso_doflush(struct luasocket *S, int mode) {
	size_t amount = 0, n;
	struct iovec iov;
	int error;

	if (mode & LSO_LINEBUF) {
		if (S->eol > 0)
			amount = S->eol;
		else if (fifo_rlen(&S->obuf) > S->opts.obuf.maxline)
			amount = S->opts.obuf.maxline;
	} else if (mode & LSO_FULLBUF) {
		if (fifo_rlen(&S->obuf) > S->opts.obuf.bufsiz)
			amount = S->opts.obuf.bufsiz;
	} else if (mode & LSO_NOBUF) {
		amount = fifo_rlen(&S->obuf);
	}

	while (amount) {
		if (!fifo_slice(&S->obuf, &iov, 0, amount))
			break; /* should never happen */

		so_clear(S->socket);

		if (!(n = so_write(S->socket, iov.iov_base, iov.iov_len, &error)))
			goto error;

		fifo_discard(&S->obuf, n);
		amount -= n;
		S->eol -= MIN(S->eol, n);
	}
	
	return 0;
error:
	switch (error) {
	case EPIPE:
		S->fin = 1;

		break;
	} /* switch() */

	return error;
} /* lso_doflush() */


static lso_nargs_t lso_send4(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	const unsigned char *src, *lf;
	size_t tp, p, pe, end, n;
	int mode, error;

	lua_settop(L, 5);

	src = luaL_checklstring(L, 2, &end);
	tp = lso_checksize(L, 3) - 1;
	pe = lso_checksize(L, 4);
	mode = lso_imode(luaL_optstring(L, 5, ""), S->opts.obuf.mode);

	luaL_argcheck(L, tp <= end, 3, "start index beyond object boundary");
	luaL_argcheck(L, pe <= end, 4, "end index beyond object boundary");

	p = tp;

	so_clear(S->socket);

	while (p < pe) {
		if (mode & (LSO_TEXT|LSO_LINEBUF)) {
			n = MIN(pe - p, S->opts.obuf.maxline);

			if ((lf = memchr(&src[p], '\n', n))) {
				n = lf - &src[p];

				if ((error = fifo_write(&S->obof, &src[p], n)))
					goto error;

				if ((mode & LSO_TEST) && (error = fifo_putc(&S->obuf, '\r')))
					goto error;

				if ((error = fifo_putc(&S->obuf, '\n')))
					goto error;

				p += n + 1;

				S->eol = fifo_rlen(&S->obuf);
			} else {
				if ((error = fifo_write(&S->obuf, &src[p], n)))
					goto error;

				p += n;
			}
		} else {
			n = MIN(pe - p, LSO_BUFSIZ);

			if ((error = fifo_write(&S->obuf, &src[p], n)))
				goto error;

			p += n;
		}

		if (fifo_rlen(&S->obuf) > S->opts.obuf.bufsiz) {
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
} /* lso_send4() */


static lso_nargs_t lso_flush(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	int mode = lso_imode(luaL_optstring(L, 2, "n"), S->opts.obuf.mode);
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


static lso_nargs_t lso_shutdown(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	int how, error;

	switch (luaL_checkoption(L, 2, "rw", (const char *[]){ "r", "w", "rw", "wr", 0 })) {
	case 0:
		how = SHUT_RD;

		S->eof = 1;

		break;
	case 1:
		how = SHUT_WR;

		S->fin = 1;

		break;
	default:
		how = SHUT_RDWR;

		S->eof = 1;
		S->fin = 1;

		break;
	} /* switch() */

	if ((error = so_shutdown(S->socket, how))) {
		lua_pushboolean(L, 0);
		lua_pushinteger(L, error);

		return 1;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* lso_shutdown() */


static lso_nargs_t lso_eof(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	lua_pushboolean(L, S->eof);
	lua_pushboolean(L, S->fin);

	return 2;
} /* lso_eof() */


/* FIXME: Refactor so we can't leak a descriptor if Lua throws an error. */
static lso_nargs_t lso_accept(lua_State *L) {
	struct luasocket *A = luaL_checkudata(L, 1, LSO_CLASS);
	struct luasocket *S;
	int fd, error;

	so_clear(A->socket);

	if (-1 == (fd = so_accept(A->socket, 0, 0, &error))) {
		if (error == EAGAIN)
			goto yield;

		goto error;
	}

	switch (luaL_checkoption(L, 2, "tcp", (const char *[]){ "tcp", "fd", 0 })) {
	case 0: default:
		S = lua_newuserdata(L, offsetof(typeof(*S), iblock) + A->opts.bufsiz);

		memset(S, 0, offsetof(typeof(*S), iblock));

		fifo_init(&S->ibuf, S->iblock, A->opts.bufsiz);
		fifo_init(&S->obuf);

		S->opts = A->opts;

		luaL_getmetatable(L, LSO_CLASS);
		lua_setmetatable(L, -2);

		if (!(S->socket = so_fdopen(fd, so_opts(), &error)))
			goto error;

		break;
	case 1:
		lua_pushinteger(L, fd);

		break;
	} /* switch() */

	return 1;
yield:
	lua_pushvalue(L, 1);

	return lua_yieldk(L, 1, EAGAIN, &lso_accept);
error:
	A->error = error;

	return errors_return(L, LUA_TNIL, &A->errors, error);
} /* lso_accept() */


static lso_nargs_t lso__gc(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	fifo_reset(&S->ibuf);
	fifo_reset(&S->obuf);

	so_close(S->socket);
	S->socket = 0;

	return 0;
} /* lso__gc() */


static luaL_Reg lso_methods[] = {
	{ "setvbuf",  &lso_setvbuf },
	{ "recv",     &lso_recv },
	{ "send4",    &lso_send4 },
	{ "flush",    &lso_flush },
	{ "clear",    &lso_clear },
	{ "shutdown", &lso_shutdown },
	{ "eof",      &lso_eof },
	{ "accept",   &lso_accept },
	{ 0, 0 }
}; /* lso_methods[] */


static luaL_Reg lso_events[] = {
	{ "__gc", &lso__gc },
	{ 0, 0 }
}; /* lso_events[] */


static luaL_Reg lso_globals[] = {
	{ "connect", &lso_connect },
	{ "listen",  &lso_listen },
	{ 0, 0 }
}; /* lso_globals[] */


static lso_nargs_t luaopen_cqueues_socket(lua_State *L) {
	if (luaL_newmetatable(L, LSO_CLASS)) {
		luaL_setfuncs(L, lso_events, 0);

		lua_newtable(L);
		luaL_setfuncs(L, lso_methods, 0);
		lua_setfield(L, -2, "__index");
	}

	lua_pop(L, 1);

	lua_newtable(L);
	luaL_setfuncs(L, lso_globals, 0);

	return 1;
} /* luaopen_cqueues_socket() */
