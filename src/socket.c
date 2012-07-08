#include <stddef.h>	/* NULL offsetof size_t */
#include <string.h>	/* memset(3) memchr(3) memcmp(3) memmem(3) */

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
			size_t bufsiz;
		} obuf;
	} opts;

	struct socket *socket;

	_Bool eof, fin;
	int error;

	struct fifo ibuf, obuf;
}; /* struct luasocket */


static size_t lso_optsize(struct lua_State *L, int index, size_t def) {
	size_t size = luaL_optunsigned(L, index, def)

	return (size)? size : def;
} /* lso_optsize() */


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
	int mode = lso_imode(luaL_checkstring(L, 2), LSO_INITMODE);

	S->opts.ibuf.mode = LSO_RDMASK(mode);
	S->opts.obuf.mode = LSO_WRMASK(mode);

	return 0;
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
	struct lso_recv rcv = { index, LSO_CHOMP, 0, mode, resume };
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


static lso_nargs_t lso_read(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	struct lso_recv rcv;
	int top, index, error;

	if (LUA_OK == lua_getctx(L, &top)) {
		if (1 == (top = lua_gettop(L))) {
			lua_pushstring(L, "*l");
			top++;
		}

		lua_pushinteger(L, 2);
	}

	index = lua_tointeger(L, top + 1);

	/* discard any lua_resume() results */
	lua_settop(L, top + 1 + (index - 2));

	while (index <= top) {
		rcv = lso_checkrecv(L, index, (S->opts.ibuf.mode|LSO_WAITALL));

		if (LUA_YIELD == lso_dorecv(L, S, &rcv))
			goto yield;

		lua_pushinteger(L, ++index);
		lua_replace(L, top + 1);
	}

	return lua_gettop(L) - (top + 1);
yield:
	lua_pushvalue(L, 1);

	return lua_yieldk(L, 1, top, &lso_read);
} /* lso_read() */


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


struct lso_callinfo {
	int top;

	struct {
		int type;

		union {
			void *p;
			size_t z;
		};
	} reg[3];
}; /* struct lso_callinfo() */





struct lso_send {
	int index;
	unsigned char *p, *pe;
	int mode;
}; /* struct lso_send */


static lso_nargs_t lso_write(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	struct lso_recv rcv;
	int top, index, error;

	if (LUA_OK == lua_getctx(L, &top)) {
		if (1 == (top = lua_gettop(L))) {
			lua_pushstring(L, "*l");
			top++;
		}

		lua_pushinteger(L, 2);
	}

	index = lua_tointeger(L, top + 1);

	/* discard any lua_resume() results */
	lua_settop(L, top + 1 + (index - 2));

	while (index <= top) {
		rcv = lso_checkrecv(L, index, (S->opts.ibuf.mode|LSO_WAITALL));

		if (LUA_YIELD == lso_dorecv(L, S, &rcv))
			goto yield;

		lua_pushinteger(L, ++index);
		lua_replace(L, top + 1);
	}

	return lua_gettop(L) - (top + 1);
yield:
	lua_pushvalue(L, 1);

	return lua_yieldk(L, 1, top, &lso_read);
} /* lso_write() */


#if 0
static lso_nargs_t lso_write(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	const char *data;
	size_t count, n;
	struct iovec iov;
	int flush = 0, error;

	if (LUA_YIELD == lua_getctx(L, &flush))
		goto flush;

	data = luaL_checklstring(L, 2, &count);

	/* ensure enough buffer is available at outset */
	if ((error = fifo_grow(&S->obuf, count)))
		goto error;

	/*
	 * if data already in buffer or we're block or line buffering,
	 * queue; otherwise, try to write out directly and then queue
	 * remainder.
	 */
	if (fifo_rlen(&S->obuf) || S->opts.obuf.type != LSO_NOBUF) {
		if ((error = fifo_write(&S->obuf, data, count)))
			goto error;
	} else {
		error = 0;

		if (!(n = so_write(S->socket, data, count, &error)) && error != EAGAIN)
			goto error;

		data += n;
		count -= n;

		if ((error = fifo_write(&S->obuf, data, count)))
			goto error;
	}

	switch (S->opts.obuf.type) {
	case LSO_LINEBUF: {
		struct fifo tail;
		size_t total;

		total = fifo_rvec(&S->obuf, &iov, 1);
		fifo_from(&tail, iov.iov_base, iov.iov_len);

		count = 0;

		while ((n = fifo_lvec(&tail, &iov))) {
			count += n;
			fifo_slice(&S->obuf, &iov, count, total - count);
			fifo_from(&tail, iov.iov_base, iov.iov_len);
		}

		break;
	}
	case LSO_FULLBUF:
		count = fifo_rlen(&S->obuf);

		if (count < S->opts.obuf.bufsiz)
			count = 0;

		break;
	case LSO_NOBUF:
		/* FALL THROUGH */
	default:
		count = fifo_rlen(&S->obuf);

		break;
	} /* switch (mode) */

	flush = (int)MIN((size_t)INT_MAX, count);

flush:
	while (flush > 0 && fifo_rvec(&S->obuf, &iov, LSO_DEFRAG)) {
		iov.iov_len = MIN((size_t)flush, iov.iov_len);

		if (!(count = so_write(S->socket, iov.iov_base, iov.iov_len, &error))) {
			if (error == EAGAIN) {
				luacq_pushevent(L, so_pollfd(S->socket), so_events(S->socket), 0, 1);

				return lua_yieldk(L, 1, flush, &lso_write);
			} else
				goto error;
		}

		fifo_discard(&S->obuf, count);
		flush -= (int)count;
	} /* while(flush) */

	lua_pushboolean(L, 1);

	return 1;
error:
	return errors_return(L, LUA_TBOOLEAN, &S->errors, error);
} /* lso_write() */
#endif


static lso_nargs_t lso_flush(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);
	struct iovec iov;
	size_t count;
	int error;

	while (fifo_rvec(&S->obuf, &iov, LSO_DEFRAG)) {
		if (!(count = so_write(S->socket, iov.iov_base, iov.iov_len, &error))) {
			if (error != EAGAIN)
				goto error;

			break;
		}

		fifo_discard(&S->obuf, count);
	}

	lua_pushboolean(L, !fifo_rlen(&S->obuf));

	return 1;
error:
	return errors_return(L, LUA_TBOOLEAN, &S->errors, error);
} /* lso_flush() */


static lso_nargs_t lso_clear(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	so_clear(S->socket);

	return 0;
} /* lso_clear() */


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
		return errors_return(L, LUA_TBOOLEAN, &S->errors, error);
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


static lso_nargs_t lso_error(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	if (S->error)
		lua_pushstring(L, so_strerror(S->error));
	else
		lua_pushnil(L);

	return 1;
} /* lso_error() */


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


static lso_nargs_t lso_onerror(lua_State *L) {
	struct luasocket *S = luaL_checkudata(L, 1, LSO_CLASS);

	return errors_onerror(L, &S->errors, 2, 3);
} /* lso_onerror() */


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
	{ "read",     &lso_read },
	{ "write",    &lso_write },
	{ "flush",    &lso_flush },
	{ "clear",    &lso_clear },
	{ "shutdown", &lso_shutdown },
	{ "eof",      &lso_eof },
	{ "error",    &lso_error },
	{ "accept",   &lso_accept },
	{ "onerror",  &lso_onerror },
	{ 0, 0 }
}; /* lso_methods[] */


static luaL_Reg lso_events[] = {
	{ "__gc", &lso__gc },
	{ 0, 0 }
}; /* lso_events[] */


static luaL_Reg lso_globals[] = {
	{ "connect", &lso_connect },
	{ "listen", &lso_listen },
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
