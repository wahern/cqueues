/* ==========================================================================
 * errno.c.m4 - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012, 2015  William Ahern
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
#include <string.h> /* memcpy(3) strcmp(3) strerror_r(3) strnlen(3) */
#include <errno.h>

#include <lua.h>
#include <lauxlib.h>

#include "lib/dns.h"
#include "lib/socket.h"

#include "cqueues.h"


#ifndef STRERROR_R_CHAR_P
#define STRERROR_R_CHAR_P ((GLIBC_PREREQ(0,0) || UCLIBC_PREREQ(0,0,0)) && (_GNU_SOURCE || !(_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600)))
#endif

cqs_error_t cqs_strerror_r(cqs_error_t error, char *dst, size_t lim) {
	const char *src;

	if (error >= DNS_EBASE && error < DNS_ELAST) {
		src = dns_strerror(error);
	} else if (error >= SO_EBASE && error < SO_ELAST) {
		src = so_strerror(error);
	} else {
#if STRERROR_R_CHAR_P
		if (!(src = strerror_r(error, dst, lim)))
			return EINVAL;
#else
		/* glibc between 2.3.4 and 2.13 returns -1 on error */
		if (-1 == (error = strerror_r(error, dst, lim)))
			return errno;

		return error;
#endif
	}

	if (src != dst && lim > 0) {
		size_t n = strnlen(src, lim - 1);
		memcpy(dst, src, n);
		dst[n] = '\0';
	}

	return 0;
} /* cqs_strerror_r() */


const char *(cqs_strerror)(int error, void *dst, size_t lim) {
	char *p, *pe, *unknown;
	char e10[((sizeof error * CHAR_BIT) / 3) + 1], *ep;
	int n;

	if (!lim)
		return dst;

	if (0 == cqs_strerror_r(error, dst, lim) && *(char *)dst)
		return dst;

	p = dst;
	pe = p + lim;

	unknown = "Unknown error: ";
	while (*unknown && p < pe)
		*p++ = *unknown++;

	if (error < 0 && p < pe)
		*p++ = '-';

	/* translate integer to string in LSB order */
	for (ep = e10, n = error; n; ep++, n /= 10)
		*ep = "0123456789"[abs(n % 10)];
	if (ep == e10)
		*ep++ = '0';

	/* copy string, flipping from LSB to MSB */
	while (ep > e10 && p < pe)
		*p++ = *--ep;

	p[-1] = '\0';

	return dst;
} /* cqs_strerror() */


static const struct {
	const char *name;
	int value;
} errlist[] = {
changequote(<<<,>>>)dnl
ifdef(<<<esyscmd>>>,<<<esyscmd>>>,<<<syscmd>>>)(<<<
../mk/errno.ls | awk '{ print "#ifdef "$1"\n\t{ \""$1"\", "$1" },\n#endif" }'
>>>)dnl
};


static int le_strerror(lua_State *L) {
	lua_pushstring(L, cqs_strerror(luaL_checkint(L, 1)));

	return 1;
} /* le_strerror() */


static const luaL_Reg le_globals[] = {
	{ "strerror", &le_strerror },
	{ NULL, NULL }
};


int luaopen__cqueues_errno(lua_State *L) {
	unsigned i;

	luaL_newlib(L, le_globals);

	for (i = 0; i < sizeof errlist / sizeof *errlist; i++) {
		lua_pushstring(L, errlist[i].name);
		lua_pushinteger(L, errlist[i].value);
		lua_settable(L, -3);

#if EAGAIN == EWOULDBLOCK
		if (!strcmp(errlist[i].name, "EWOULDBLOCK"))
			continue;
#endif

		lua_pushinteger(L, errlist[i].value);
		lua_pushstring(L, errlist[i].name);
		lua_settable(L, -3);
	}

	return 1;
} /* luaopen__cqueues_errno() */
