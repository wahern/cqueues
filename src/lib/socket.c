/* ==========================================================================
 * socket.c - Simple Sockets
 * --------------------------------------------------------------------------
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015  William Ahern
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
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h> /* offsetof size_t */
#include <limits.h> /* INT_MAX LONG_MAX */
#include <stdlib.h> /* malloc(3) free(3) */
#include <string.h> /* strdup(3) strlen(3) memset(3) strncpy(3) memcpy(3) strerror(3) */
#include <errno.h>  /* EINVAL EAFNOSUPPORT EAGAIN EWOULDBLOCK EINPROGRESS EALREADY ENAMETOOLONG EOPNOTSUPP ENOTSOCK ENOPROTOOPT */
#include <signal.h> /* SIGPIPE SIG_BLOCK SIG_SETMASK sigset_t sigprocmask(2) pthread_sigmask(3) sigtimedwait(2) sigpending(2) sigemptyset(3) sigismember(3) sigaddset(3) */
#include <assert.h> /* assert(3) */
#include <time.h>   /* time(2) */

#include <sys/types.h>   /* socklen_t mode_t in_port_t */
#include <sys/stat.h>    /* fchmod(2) fstat(2) S_IFSOCK S_ISSOCK */
#include <sys/select.h>  /* FD_ZERO FD_SET fd_set select(2) */
#include <sys/socket.h>  /* AF_UNIX AF_INET AF_INET6 SO_TYPE SO_NOSIGPIPE MSG_EOR MSG_NOSIGNAL struct sockaddr_storage socket(2) connect(2) bind(2) listen(2) accept(2) getsockname(2) getpeername(2) */
#if defined(AF_UNIX)
#include <sys/un.h>      /* struct sockaddr_un struct unpcbid */
#endif
#include <netinet/in.h>  /* IPPROTO_IPV6 IPPROTO_TCP IPV6_V6ONLY struct sockaddr_in struct sockaddr_in6 */
#include <netinet/tcp.h> /* TCP_NODELAY TCP_NOPUSH TCP_CORK */
#include <arpa/inet.h>   /* inet_ntop(3) inet_pton(3) ntohs(3) htons(3) */
#include <netdb.h>       /* struct addrinfo */
#include <unistd.h>      /* _POSIX_REALTIME_SIGNALS _POSIX_THREADS close(2) unlink(2) getpeereid(2) */
#include <fcntl.h>       /* F_SETFD F_GETFD F_GETFL F_SETFL FD_CLOEXEC O_NONBLOCK O_NOSIGPIPE F_SETNOSIGPIPE F_GETNOSIGPIPE */
#include <poll.h>        /* POLLIN POLLOUT */
#if defined __sun
#include <ucred.h>       /* ucred_t getpeerucred(2) ucred_free(3) */
#endif

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "dns.h"
#include "socket.h"


/*
 * V E R S I O N  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

const char *socket_vendor(void) {
	return SOCKET_VENDOR;
} /* socket_vendor() */


int socket_v_rel(void) {
	return SOCKET_V_REL;
} /* socket_v_rel() */


int socket_v_abi(void) {
	return SOCKET_V_ABI;
} /* socket_v_abi() */


int socket_v_api(void) {
	return SOCKET_V_API;
} /* socket_v_api() */


/*
 * F E A T U R E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !defined SO_THREAD_SAFE
#if (defined _REENTRANT || defined _THREAD_SAFE) && _POSIX_THREADS > 0
#define SO_THREAD_SAFE 1
#else
#define SO_THREAD_SAFE 0
#endif
#endif

#ifndef HAVE_OPENSSL11_API
#define HAVE_OPENSSL11_API (!(OPENSSL_VERSION_NUMBER < 0x10100001L || defined LIBRESSL_VERSION_NUMBER))
#endif

#ifndef HAVE_BIO_CTRL_SET_CONNECTED_2ARY
#define HAVE_BIO_CTRL_SET_CONNECTED_2ARY HAVE_OPENSSL11_API
#endif

#ifndef HAVE_BIO_SET_INIT
#define HAVE_BIO_SET_INIT HAVE_OPENSSL11_API
#endif

#ifndef HAVE_BIO_SET_SHUTDOWN
#define HAVE_BIO_SET_SHUTDOWN HAVE_OPENSSL11_API
#endif

#ifndef HAVE_BIO_SET_DATA
#define HAVE_BIO_SET_DATA HAVE_OPENSSL11_API
#endif

#ifndef HAVE_BIO_GET_DATA
#define HAVE_BIO_GET_DATA HAVE_OPENSSL11_API
#endif

#ifndef HAVE_BIO_UP_REF
#define HAVE_BIO_UP_REF HAVE_OPENSSL11_API
#endif

#ifndef HAVE_SSL_IS_SERVER
#define HAVE_SSL_IS_SERVER HAVE_OPENSSL11_API
#endif

#ifndef HAVE_SSL_UP_REF
#define HAVE_SSL_UP_REF HAVE_OPENSSL11_API
#endif


/*
 * C O M P A T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !HAVE_BIO_CTRL_SET_CONNECTED_2ARY
#undef BIO_ctrl_set_connected
#define BIO_ctrl_set_connected(b, peer) (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)peer)
#endif

#if !HAVE_BIO_SET_INIT
#define BIO_set_init(bio, val) ((void)((bio)->init = (val)))
#endif

#if !HAVE_BIO_SET_SHUTDOWN
#define BIO_set_shutdown(bio, val) ((void)((bio)->shutdown = (val)))
#endif

#if !HAVE_BIO_SET_DATA
#define BIO_set_data(bio, val) ((void)((bio)->ptr = (val)))
#endif

#if !HAVE_BIO_GET_DATA
#define BIO_get_data(bio) ((bio)->ptr)
#endif

#if !HAVE_BIO_UP_REF
#define BIO_up_ref(bio) CRYPTO_add(&(bio)->references, 1, CRYPTO_LOCK_BIO)
#endif

#if !HAVE_SSL_IS_SERVER
#undef SSL_is_server
#define SSL_is_server(ssl) compat_SSL_is_server(ssl)

static _Bool compat_SSL_is_server(SSL *ssl) {
	const SSL_METHOD *method = SSL_get_ssl_method(ssl);

	/*
	 * NOTE: SSLv23_server_method()->ssl_connect should be a reference to
	 * OpenSSL's internal ssl_undefined_function().
	 *
	 * Server methods such as TLSv1_2_server_method(), etc. should have
	 * their .ssl_connect method set to this value.
	 *
	 * WARNING: SSL_is_server in OpenSSL 1.1 defaults to server mode
	 * when both connect and accept methods are present (e.g. as
	 * returned by SSLv23_method()), whereas we always defaulted to
	 * client mode. We keep our old logic to avoid breaking any existing
	 * code that relies on our behavior. Such code will break when
	 * moving to OpenSSL 1.1, but it would be even more surprising if
	 * their code broke when the only change was a minor version of
	 * something using this library.
	 */
	if (!method->ssl_connect || method->ssl_connect == SSLv23_server_method()->ssl_connect)
		return 1;

	return 0;
} /* compat_SSL_is_server() */
#endif

#if !HAVE_SSL_UP_REF
#define SSL_up_ref(...) compat_SSL_up_ref(__VA_ARGS__)

static int compat_SSL_up_ref(SSL *ssl) {
	/* our caller should already have had a proper reference */
	if (CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL) < 2)
		return 0; /* fail */

	return 1;
} /* compat_SSL_up_ref() */
#endif


/*
 * D E B U G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int socket_debug;


enum so_trace {
	SO_T_CONNECT,
	SO_T_STARTTLS,
	SO_T_READ,
	SO_T_WRITE,
}; /* enum so_trace */


static void so_trace(enum so_trace, int, const struct addrinfo *, ...);


#if !defined(SOCKET_DEBUG)
#define SOCKET_DEBUG 0
#endif

#if SOCKET_DEBUG

#include <stdio.h>
#include <stdarg.h>

#include <ctype.h>


#undef SOCKET_DEBUG
#define SOCKET_DEBUG socket_debug


#if !defined(SAY)
#define SAY_(fmt, ...) fprintf(stderr, fmt "%s", __FILE__, __LINE__, __func__, __VA_ARGS__);
#define SAY(...) SAY_("@@ %s:%d:%s: " __VA_ARGS__, "\n");
#endif

#if !defined(HAI)
#define HAI SAY_("@@ %s:%d:%s", "\n");
#endif


static void so_dump(const unsigned char *src, size_t len, FILE *fp) {
	static const unsigned char hex[] = "0123456789abcdef";
	static const unsigned char tmp[] = "                                                            |                |\n";
	unsigned char ln[sizeof tmp];
	const unsigned char *p, *pe;
	unsigned char *h, *g;
	unsigned i, n;

	p  = src;
	pe = p + len;

	while (p < pe) {
		memcpy(ln, tmp, sizeof ln);

		h = &ln[2];
		g = &ln[61];

		n = p - src;
		h[0] = hex[0x0f & (n >> 20)];
		h[1] = hex[0x0f & (n >> 16)];
		h[2] = hex[0x0f & (n >> 12)];
		h[3] = hex[0x0f & (n >> 8)];
		h[4] = hex[0x0f & (n >> 4)];
		h[5] = hex[0x0f & (n >> 0)];
		h += 8;

		for (n = 0; n < 2; n++) {
			for (i = 0; i < 8 && pe - p > 0; i++, p++) {
				h[0] = hex[0x0f & (*p >> 4)];
				h[1] = hex[0x0f & (*p >> 0)];
				h += 3;

				*g++ = (isgraph(*p))? *p : '.';
			}

			h++;
		}

		fputs((char *)ln, fp);
	}
} /* so_dump() */


static void so_trace(enum so_trace event, int fd, const struct addrinfo *host, ...) {
	struct sockaddr_storage saddr = {0};
	socklen_t saddr_len = sizeof saddr;
	char addr[64], who[256];
	in_port_t port;
	va_list ap;
	SSL *ctx;
	const void *data;
	size_t count;
	const char *fmt;
	int error;

	if (!socket_debug)
		return;

	if (host) {
		sa_ntop(addr, sizeof addr, host->ai_addr, NULL, &error);
		port = *sa_port(host->ai_addr, SA_PORT_NONE, NULL);

		if (host->ai_canonname)
			snprintf(who, sizeof who, "%.96s/[%s]:%hu", host->ai_canonname, addr, ntohs(port));
		else
			snprintf(who, sizeof who, "[%s]:%hu", addr, ntohs(port));
	} else if (fd != -1 && 0 == getpeername(fd, (struct sockaddr *)&saddr, &saddr_len)) {
		sa_ntop(addr, saddr_len, &saddr, NULL, &error);
		port = *sa_port(&saddr, SA_PORT_NONE, NULL);

		snprintf(who, sizeof who, "[%s]:%hu", addr, ntohs(port));
	} else
		dns_strlcpy(who, "[unknown]", sizeof who);

	va_start(ap, host);

	flockfile(stderr);

	switch (event) {
	case SO_T_CONNECT:
		fmt = va_arg(ap, char *);

		fprintf(stderr, "connect(%s): ", who);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);

		break;
	case SO_T_STARTTLS:
		ctx = va_arg(ap, SSL *);
		fmt = va_arg(ap, char *);

		(void)ctx; /* unused for now */
		fprintf(stderr, "starttls(%s): ", who);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);

		break;
	case SO_T_READ:
		data  = va_arg(ap, void *);
		count = va_arg(ap, size_t);
		fmt   = va_arg(ap, char *);

		fprintf(stderr, "read(%s): ", who);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);

		so_dump(data, count, stderr);

		break;
	case SO_T_WRITE:
		data  = va_arg(ap, void *);
		count = va_arg(ap, size_t);
		fmt   = va_arg(ap, char *);

		fprintf(stderr, "write(%s): ", who);
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);

		so_dump(data, count, stderr);

		break;
	} /* switch(event) */

	funlockfile(stderr);

	va_end(ap);
} /* so_trace() */


static void so_initdebug(void) {
	const char *debug;

	if ((debug = getenv("SOCKET_DEBUG")) || (debug = getenv("SO_DEBUG"))) {
		switch (*debug) {
		case 'Y': case 'y':
		case 'T': case 't':
		case '1':
			socket_debug = 1;

			break;
		case 'N': case 'n':
		case 'F': case 'f':
		case '0':
			socket_debug = 0;

			break;
		} /* switch() */
	}
} /* so_initdebug() */


#else

#define so_trace(...) (void)0

#define so_initdebug() (void)0

#endif /* SOCKET_DEBUG */


/*
 * M A C R O  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef countof
#define countof(a) (sizeof (a) / sizeof *(a))
#endif

#ifndef endof
#define endof(a) (&(a)[countof(a)])
#endif


/*
 * E R R O R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if _WIN32

#define SO_EINTR	WSAEINTR
#define SO_EINPROGRESS	WSAEINPROGRESS
#define SO_EISCONN	WSAEISCONN
#define SO_EWOULDBLOCK	WSAEWOULDBLOCK
#define SO_EALREADY	WSAEALREADY
#define SO_EAGAIN	WSAEWOULDBLOCK
#define SO_ENOTCONN	WSAENOTCONN
#define SO_ECONNABORTED WSAECONNABORTED

#define so_syerr()	((int)GetLastError())
#define so_soerr()	((int)WSAGetLastError())

#else

#define SO_EINTR	EINTR
#define SO_EINPROGRESS	EINPROGRESS
#define SO_EISCONN	EISCONN
#define SO_EWOULDBLOCK	EWOULDBLOCK
#define SO_EALREADY	EALREADY
#define SO_EAGAIN	EAGAIN
#define SO_ENOTCONN	ENOTCONN
#define SO_ECONNABORTED ECONNABORTED

#define so_syerr()	errno
#define so_soerr()	errno

#endif


const char *so_strerror(int error) {
	static const char *errlist[] = {
		[SO_EOPENSSL - SO_ERRNO0] = "TLS/SSL error",
		[SO_EX509INT - SO_ERRNO0] = "X.509 certificate lookup interrupt",
		[SO_ENOTVRFD - SO_ERRNO0] = "Absent or unverified peer certificate",
		[SO_ECLOSURE - SO_ERRNO0] = "Peers elected to shutdown secure transport",
		[SO_ENOHOST - SO_ERRNO0]  = "No host address available to complete operation",
	};

	if (error >= 0)
		return strerror(error);

	if (error == SO_EOPENSSL) {
#if SO_THREAD_SAFE && (!defined __NetBSD__ || __NetBSD_Version__ > 600000000)
		static __thread char sslstr[256];
#else
		static char sslstr[256];
#endif
		unsigned long code = ERR_peek_last_error();

		if (!code)
			return "Unknown TLS/SSL error";

		ERR_error_string_n(code, sslstr, sizeof sslstr);

		return sslstr;
	} else {
		int index = error - SO_ERRNO0;

		if (index >= 0 && index < (int)countof(errlist) && errlist[index])
			return errlist[index];
		else
			return "Unknown socket error";
	}
} /* so_strerror() */


/*
 * Translate SSL_get_error(3) errors into something sensible.
 */
static int ssl_error(SSL *ctx, int rval, short *events) {
	unsigned long code;

	switch (SSL_get_error(ctx, rval)) {
	case SSL_ERROR_ZERO_RETURN:
		return SO_ECLOSURE;
	case SSL_ERROR_WANT_READ:
		*events |= POLLIN;

		return SO_EAGAIN;
	case SSL_ERROR_WANT_WRITE:
		*events |= POLLOUT;

		return SO_EAGAIN;
	case SSL_ERROR_WANT_CONNECT:
		*events |= POLLOUT;

		return SO_EAGAIN;
	case SSL_ERROR_WANT_ACCEPT:
		*events |= POLLIN;

		return SO_EAGAIN;
	case SSL_ERROR_WANT_X509_LOOKUP:
		return SO_EX509INT;
	case SSL_ERROR_SYSCALL:
		if ((code = ERR_peek_last_error()))
			return SO_EOPENSSL;
		else if (rval == 0)
			return ECONNRESET;
		else if (rval == -1 && so_soerr() && so_soerr() != SO_EAGAIN)
			return so_soerr();
		else
			return SO_EOPENSSL;
	case SSL_ERROR_SSL:
		/* FALL THROUGH */
	default:
		return SO_EOPENSSL;
	} /* switch(SSL_get_error()) */
} /* ssl_error() */


/*
 * A D D R E S S  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

char *sa_ntop(char *dst, size_t lim, const void *src, const char *def, int *_error) {
	union sockaddr_any *any = (void *)src;
	const char *unspec = "0.0.0.0";
	char text[SA_ADDRSTRLEN];
	int error;

	switch (*sa_family(&any->sa)) {
	case AF_INET:
		unspec = "0.0.0.0";

		if (!inet_ntop(AF_INET, &any->sin.sin_addr, text, sizeof text))
			goto syerr;

		break;
	case AF_INET6:
		unspec = "::";

		if (!inet_ntop(AF_INET6, &any->sin6.sin6_addr, text, sizeof text))
			goto syerr;

		break;
#if SA_UNIX
	case AF_UNIX:
		unspec = "/nonexistent";

		memset(text, 0, sizeof text);
		memcpy(text, any->sun.sun_path, SO_MIN(sizeof text - 1, sizeof any->sun.sun_path));

		break;
#endif
	default:
		error = EAFNOSUPPORT;

		goto error;
	} /* switch() */

	if (dns_strlcpy(dst, text, lim) >= lim) {
		error = ENOSPC;

		goto error;
	}

	return dst;
syerr:
	error = so_syerr();
error:
	if (_error)
		*_error = error;

	/*
	 * NOTE: Always write something in case caller ignores errors, such
	 * as when caller is using the sa_ntoa() macro.
	 */
	dns_strlcpy(dst, (def)? def : unspec, lim);

	return (char *)def;
} /* sa_ntop() */


void *sa_pton(void *dst, size_t lim, const char *src, const void *def, int *_error) {
	union sockaddr_any family[] = { { { .sa_family = AF_INET } }, { { .sa_family = AF_INET6 } } }, *fp;
	int error;

	memset(dst, 0, lim);

	for (fp = family; fp < endof(family); fp++) {
		switch (inet_pton(*sa_family(fp), src, sa_addr(fp, NULL, NULL))) {
		case -1:
			goto syerr;
		case 1:
			if (lim < sa_len(fp)) {
				error = ENOSPC;

				goto error;
			}

			memcpy(dst, fp, sa_len(fp));

			return dst;
		}
	}

	error = EAFNOSUPPORT;

	goto error;
syerr:
	error = so_syerr();
error:
	if (_error)
		*_error = error;

	return (void *)def;
} /* sa_pton() */


/*
 * U T I L I T I Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void *sa_egress(void *lcl, size_t lim, sockaddr_arg_t rmt, int *_error) {
	static struct { sa_family_t pf; int fd;} udp4 = { PF_INET, -1 }, udp6 = { PF_INET6, -1 }, *udp;
	struct sockaddr_storage ss;
	int error;

	switch (*sa_family(rmt)) {
	case AF_INET:
		udp = &udp4;

		break;
	case AF_INET6:
		udp = &udp6;

		break;
	default:
		error = EINVAL;

		goto error;
	}

	if (udp->fd == -1) {
#if defined SOCK_CLOEXEC
		if (-1 == (udp->fd = socket(udp->pf, SOCK_DGRAM|SOCK_CLOEXEC, 0)))
			goto syerr;
#else
		if (-1 == (udp->fd = socket(udp->pf, SOCK_DGRAM, 0)))
			goto syerr;
#endif

		if ((error = so_cloexec(udp->fd, 1))) {
			so_closesocket(&udp->fd, NULL);

			goto error;
		}
	}

	assert(sizeof ss >= sa_len(rmt));
	memcpy(&ss, sockaddr_ref(rmt).sa, sa_len(rmt));

	if (!*sa_port(&ss, SA_PORT_NONE, NULL))
		*sa_port(&ss, SA_PORT_NONE, NULL) = htons(6970);

	if (0 != connect(udp->fd, (struct sockaddr *)&ss, sa_len(&ss)))
		goto syerr;

	memset(&ss, 0, sizeof ss);

	if (0 != getsockname(udp->fd, (struct sockaddr *)&ss, &(socklen_t){ sizeof ss }))
		goto syerr;

	if (lim < sa_len(&ss)) {
		error = ENOSPC;

		goto error;
	}

	memcpy(lcl, &ss, sa_len(&ss));

	return lcl;
syerr:
	error = so_syerr();
error:
	if (_error)
		*_error = error;

	return memset(lcl, 0, lim);
} /* sa_egress() */


static so_error_t so_ffamily(int fd, int *family) {
	struct sockaddr_storage ss;

	if (0 != getsockname(fd, (struct sockaddr *)&ss, &(socklen_t){ sizeof ss }))
		return errno;

	*family = ss.ss_family;

	return 0;
} /* so_ffamily() */


static so_error_t so_ftype(int fd, mode_t *mode, int *domain, int *type, int *protocol) {
	struct stat st;
	int error;

	if (0 != fstat(fd, &st))
		return errno;

	*mode = S_IFMT & st.st_mode;

	if (!S_ISSOCK(*mode))
		return 0;

#if defined SO_DOMAIN
	if (0 != getsockopt(fd, SOL_SOCKET, SO_DOMAIN, domain, &(socklen_t){ sizeof *domain })) {
		if (errno != ENOPROTOOPT)
			return errno;

		if ((error = so_ffamily(fd, domain)))
			return error;
	}
#else
	if ((error = so_ffamily(fd, domain)))
		return error;
#endif

	if (0 != getsockopt(fd, SOL_SOCKET, SO_TYPE, type, &(socklen_t){ sizeof *type }))
		return errno;

#if defined SO_PROTOCOL
	if (0 != getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, protocol, &(socklen_t){ sizeof *protocol })) {
		if (errno != ENOPROTOOPT)
			return errno;
	}
#else
	(void)protocol;
#endif

	return 0;
} /* so_ftype() */


static int so_opts2flags(const struct so_options *, int *);
static int so_type2mask(mode_t, int, int, int);

int so_socket(int domain, int type, const struct so_options *opts, int *_error) {
	int error, fd, flags, mask, need;

#if defined SOCK_CLOEXEC
	if (-1 == (fd = socket(domain, type|SOCK_CLOEXEC, 0)))
		goto syerr;
#else
	if (-1 == (fd = socket(domain, type, 0)))
		goto syerr;
#endif

	flags = so_opts2flags(opts, &mask);
	mask &= so_type2mask(S_IFSOCK, domain, type, 0);
	need = ~(SO_F_NODELAY|SO_F_NOPUSH|SO_F_NOSIGPIPE|SO_F_OOBINLINE);

	if ((error = so_setfl(fd, flags, mask, need)))
		goto error;

	return fd;
syerr:
	error = so_syerr();

	goto error;
error:
	*_error = error;

	so_closesocket(&fd, opts);

	return -1;
} /* so_socket() */


#define so_bind(...) SO_EXTENSION so_bind(__VA_ARGS__)

int (so_bind)(int fd, sockaddr_arg_t arg, const struct so_options *opts) {
#if SA_UNIX
	if (*sa_family(arg) == AF_UNIX) {
		char *path = strncpy((char [sizeof sockaddr_ref(arg).sun->sun_path + 1]){ 0 }, sockaddr_ref(arg).sun->sun_path, sizeof sockaddr_ref(arg).sun->sun_path);
		_Bool nochmod = 0;
		int error;

		if (opts->sun_unlink && *path)
			(void)unlink(path);

		if (opts->sun_mode) {
			if (0 == fchmod(fd, (opts->sun_mode & 0777)))
				nochmod = 1;
			else if (errno != EINVAL) /* BSDs return EINVAL */
				return errno;
		}

		if (opts->sun_mask) {
			mode_t omask = umask(opts->sun_mask & 0777);
			error = (0 == bind(fd, sockaddr_ref(arg).sa, sa_len(arg)))? 0 : errno;
			umask(omask);
		} else {
			error = (0 == bind(fd, sockaddr_ref(arg).sa, sa_len(arg)))? 0 : errno;
		}

		if (error)
			return error;

		if (opts->sun_mode && !nochmod && *path) {
			if (0 != chmod(path, (opts->sun_mode & 0777)))
				return errno;
		}

		return 0;
	}
#endif

	if (0 != bind(fd, sockaddr_ref(arg).sa, sa_len(arg)))
		return so_soerr();

	return 0;
} /* so_bind() */


void so_closesocket(int *fd, const struct so_options *opts) {
	if (opts && opts->fd_close.cb)
		opts->fd_close.cb(fd, opts->fd_close.arg);

	if (*fd != -1) {
#if _WIN32
		closesocket(*fd);
#else
		close(*fd);
#endif

		*fd = -1;
	}
} /* so_closesocket() */


int so_cloexec(int fd, _Bool cloexec) {
#if _WIN32
	return 0;
#else
	if (-1 == fcntl(fd, F_SETFD, cloexec))
		return so_syerr();

	return 0;
#endif
} /* so_cloexec() */


int so_nonblock(int fd, _Bool nonblock) {
	int flags, mask = (nonblock)? ~0 : (~O_NONBLOCK);

	if (-1 == (flags = fcntl(fd, F_GETFL))
	||  -1 == fcntl(fd, F_SETFL, mask & (flags | O_NONBLOCK)))
		return so_syerr();

	return 0;
} /* so_nonblock() */


static _Bool so_getboolopt(int fd, int lvl, int opt) {
	int val;

	if (0 != getsockopt(fd, lvl, opt, &val, &(socklen_t){ sizeof val }))
		return 0;

	return !!val;
} /* so_getboolopt() */


static int so_setboolopt(int fd, int lvl, int opt, _Bool enable) {
	if (0 != setsockopt(fd, lvl, opt, &(int){ enable }, sizeof (int))) {
		switch (errno) {
		case ENOTSOCK:
			/* FALL THROUGH */
		case ENOPROTOOPT:
			return EOPNOTSUPP;
		default:
			return errno;
		}
	}

	return 0;
} /* so_setboolopt() */


int so_reuseaddr(int fd, _Bool reuseaddr) {
	return so_setboolopt(fd, SOL_SOCKET, SO_REUSEADDR, reuseaddr);
} /* so_reuseaddr() */


int so_reuseport(int fd, _Bool reuseport) {
	int error;
#if defined SO_REUSEPORT
	error = so_setboolopt(fd, SOL_SOCKET, SO_REUSEPORT, reuseport);
#else
	(void)fd;
	error = EOPNOTSUPP;
#endif
	if (error == EOPNOTSUPP && !reuseport)
		error = 0; /* already disabled */

	return error;
} /* so_reuseport() */


int so_broadcast(int fd, _Bool broadcast) {
	return so_setboolopt(fd, SOL_SOCKET, SO_BROADCAST, broadcast);
} /* so_broadcast() */


int so_nodelay(int fd, _Bool nodelay) {
	return so_setboolopt(fd, IPPROTO_TCP, TCP_NODELAY, nodelay);
} /* so_nodelay() */


#ifndef TCP_NOPUSH
#ifdef TCP_CORK
#define TCP_NOPUSH TCP_CORK
#endif
#endif

int so_nopush(int fd, _Bool nopush) {
#ifdef TCP_NOPUSH
	return so_setboolopt(fd, IPPROTO_TCP, TCP_NOPUSH, nopush);
#else
	return EOPNOTSUPP;
#endif
} /* so_nopush() */


int so_nosigpipe(int fd, _Bool nosigpipe) {
#if defined O_NOSIGPIPE
	int flags, mask = (nosigpipe)? ~0 : (~O_NOSIGPIPE);

	if (-1 == (flags = fcntl(fd, F_GETFL))
	||  -1 == fcntl(fd, F_SETFL, mask & (flags | O_NOSIGPIPE)))
		return errno;

	return 0;
#elif defined F_SETNOSIGPIPE
	if (0 != fcntl(fd, F_SETNOSIGPIPE, nosigpipe))
		return errno;

	return 0;
#elif defined SO_NOSIGPIPE
	return so_setboolopt(fd, SOL_SOCKET, SO_NOSIGPIPE, nosigpipe);
#else
	(void)fd;
	(void)nosigpipe;

	return EOPNOTSUPP;
#endif
} /* so_nosigpipe() */


int so_v6only(int fd, _Bool v6only) {
	/*
	 * NOTE: OS X will return EINVAL if socket already connected.
	 * Haven't checked other systems. Should we should suppress this
	 * error?
	 */
	return so_setboolopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, v6only);
} /* so_v6only() */


int so_oobinline(int fd, _Bool oobinline) {
	return so_setboolopt(fd, SOL_SOCKET, SO_OOBINLINE, oobinline);
} /* so_oobinline() */


#define NO_OFFSET ((size_t)-1)
#define optoffset(m) offsetof(struct so_options, m)

static const struct flops {
	int flag;
	int (*set)(int, _Bool);
	size_t offset;
} fltable[] = {
	{ SO_F_CLOEXEC,   &so_cloexec,   optoffset(fd_cloexec),    },
	{ SO_F_NONBLOCK,  &so_nonblock,  optoffset(fd_nonblock),   },
	{ SO_F_REUSEADDR, &so_reuseaddr, optoffset(sin_reuseaddr), },
	{ SO_F_REUSEPORT, &so_reuseport, optoffset(sin_reuseport), },
	{ SO_F_BROADCAST, &so_broadcast, optoffset(sin_broadcast), },
	{ SO_F_NODELAY,   &so_nodelay,   optoffset(sin_nodelay),   },
	{ SO_F_NOPUSH,    &so_nopush,    optoffset(sin_nopush),    },
	{ SO_F_NOSIGPIPE, &so_nosigpipe, optoffset(fd_nosigpipe),  },
	{ SO_F_V6ONLY,    &so_v6only,    NO_OFFSET,                },
	{ SO_F_OOBINLINE, &so_oobinline, optoffset(sin_oobinline), },
};


static int so_opts2flags(const struct so_options *opts, int *mask) {
	const struct flops *f;
	int flags = 0;

	*mask = 0;

	for (f = fltable; f < endof(fltable); f++) {
		if (f->offset == NO_OFFSET)
			continue;

		flags |= (*(_Bool *)((char *)opts + f->offset))? f->flag : 0;
		*mask |= f->flag;
	}

	switch (opts->sin_v6only) {
	case SO_V6ONLY_DEFAULT:
		break;
	case SO_V6ONLY_ENABLE:
		flags |= SO_F_V6ONLY;
		*mask |= SO_F_V6ONLY;
		break;
	case SO_V6ONLY_DISABLE:
		*mask |= SO_F_V6ONLY;
		break;
	}

	return flags;
} /* so_opts2flags() */


static int so_type2mask(mode_t mode, int family, int type, int protocol) {
	int mask = SO_F_CLOEXEC|SO_F_NONBLOCK|SO_F_NOSIGPIPE;

	if (S_ISSOCK(mode)) {
		mask |= SO_F_REUSEADDR|SO_F_REUSEPORT|SO_F_OOBINLINE;

		if (!protocol) {
			if (family == AF_INET || family == AF_INET6) {
				protocol = (type == SOCK_STREAM)? IPPROTO_TCP : IPPROTO_UDP;
			}
		}

		if (family == AF_INET6) {
			mask |= SO_F_V6ONLY;
		}

		if (type == SOCK_DGRAM) {
			mask |= SO_F_BROADCAST;
		}

		if (protocol == IPPROTO_TCP) {
			mask |= SO_F_NODELAY|SO_F_NOPUSH;
		}
	}

	return mask;
} /* so_type2mask() */


int so_getfl(int fd, int which) {
	int flags = 0, getfl = 0, getfd;

	if ((which & SO_F_CLOEXEC) && -1 != (getfd = fcntl(fd, F_GETFD))) {
		if (getfd & FD_CLOEXEC)
			flags |= SO_F_CLOEXEC;
	}

	if ((which & SO_F_NONBLOCK) && -1 != (getfl = fcntl(fd, F_GETFL))) {
		if (getfl & O_NONBLOCK)
			flags |= SO_F_NONBLOCK;
	}

	if ((which & SO_F_REUSEADDR) && so_getboolopt(fd, SOL_SOCKET, SO_REUSEADDR))
		flags |= SO_F_REUSEADDR;

#if defined SO_REUSEPORT
	if ((which & SO_F_REUSEPORT) && so_getboolopt(fd, SOL_SOCKET, SO_REUSEPORT))
		flags |= SO_F_REUSEPORT;
#endif

	if ((which & SO_F_BROADCAST) && so_getboolopt(fd, SOL_SOCKET, SO_BROADCAST))
		flags |= SO_F_BROADCAST;

	if ((which & SO_F_NODELAY) && so_getboolopt(fd, IPPROTO_TCP, TCP_NODELAY))
		flags |= SO_F_NODELAY;

#if defined TCP_NOPUSH
	if ((which & SO_F_NOPUSH) && so_getboolopt(fd, IPPROTO_TCP, TCP_NOPUSH))
		flags |= SO_F_NOPUSH;
#endif

#if defined O_NOSIGPIPE || defined F_GETNOSIGPIPE || defined SO_NOSIGPIPE
	if ((which & SO_F_NOSIGPIPE)) {
#if defined O_NOSIGPIPE
		if (getfl) {
			if (getfl != -1 && (getfl & O_NOSIGPIPE))
				flags |= SO_F_NOSIGPIPE;
		} else if (-1 != (getfl = fcntl(fd, F_GETFL))) {
			if (getfl & O_NOSIGPIPE)
				flags |= SO_F_NOSIGPIPE;
		}
#elif defined F_GETNOSIGPIPE
		int nosigpipe;

		if (-1 != (nosigpipe = fcntl(fd, F_GETNOSIGPIPE))) {
			if (nosigpipe)
				flags |= SO_F_NOSIGPIPE;
		}
#else
		if (so_getboolopt(fd, SOL_SOCKET, SO_NOSIGPIPE))
			flags |= SO_F_NOSIGPIPE;
#endif
	}
#endif

	if ((which & SO_F_V6ONLY) && so_getboolopt(fd, IPPROTO_IPV6, IPV6_V6ONLY))
		flags |= SO_F_V6ONLY;

	if ((which & SO_F_OOBINLINE) && so_getboolopt(fd, SOL_SOCKET, SO_OOBINLINE))
		flags |= SO_F_OOBINLINE;

	return flags;
} /* so_getfl() */


int so_rstfl(int fd, int *oflags, int flags, int mask, int require) {
	const struct flops *f;
	int error;

	for (f = fltable; f < endof(fltable); f++) {
		if (!(f->flag & mask))
			continue;

		if ((error = f->set(fd, !!(f->flag & flags)))) {
			if ((f->flag & require) || error != EOPNOTSUPP)
				return error;

			*oflags &= ~f->flag;
		} else {
			*oflags &= ~f->flag;
			*oflags |= (f->flag & flags);
		}
	}

	return 0;
} /* so_rstfl() */


int so_setfl(int fd, int flags, int mask, int require) {
	return so_rstfl(fd, &(int){ 0 }, flags, mask, require);
} /* so_setfl() */


int (so_addfl)(int fd, int flags, int require) {
	return so_rstfl(fd, &(int){ 0 }, flags, flags, require);
} /* so_addfl() */


int (so_delfl)(int fd, int flags, int require) {
	return so_rstfl(fd, &(int){ 0 }, ~flags, flags, require);
} /* so_delfl() */


static void x509_discard(X509 **cert) {
	if (*cert)
		X509_free(*cert);
	*cert = 0;
} /* x509_discard() */


static void ssl_discard(SSL **ctx) {
	if (*ctx)
		SSL_free(*ctx);
	*ctx = 0;
} /* ssl_discard() */


static int thr_sigmask(int how, const sigset_t *set, sigset_t *oset) {
#if SO_THREAD_SAFE
	return pthread_sigmask(how, set, oset);
#else
	return (0 == sigprocmask(how, set, oset))? 0 : errno;
#endif
} /* thr_sigmask() */


static int math_addull(unsigned long long *x, unsigned long long a, unsigned long long b) {
	if (~a < b) {
		*x = ~0ULL;

		return EOVERFLOW;
	} else {
		*x = a + b;

		return 0;
	}
} /* math_addull() */


static void st_update(struct st_log *log, size_t len, const struct so_options *opts) {
	math_addull(&log->count, log->count, len);

	if (opts->st_time)
		time(&log->time);
} /* st_update() */


/*
 * S O C K E T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * NOTE: We give SO_S_SHUTWR higher precedence because on some systems
 * shutdown(SHUT_RD) will fail if EOF has already been sent by the peer. A
 * mitigation was already committed to address this issue (see so_shutrd_),
 * but it never made it downstream. This makes merging easier and is
 * otherwise sensible on its own terms.
 */
enum so_state {
	SO_S_INIT     = 1<<0,
	SO_S_GETADDR  = 1<<1,
	SO_S_SOCKET   = 1<<2,
	SO_S_BIND     = 1<<3,
	SO_S_LISTEN   = 1<<4,
	SO_S_CONNECT  = 1<<5,
	SO_S_STARTTLS = 1<<6,
	SO_S_SETREAD  = 1<<7,
	SO_S_SETWRITE = 1<<8,
	SO_S_RSTLOWAT = 1<<9,
	SO_S_SHUTWR   = 1<<10, /* see NOTE above */
	SO_S_SHUTRD   = 1<<11,

	SO_S_END,
	SO_S_ALL = ((SO_S_END - 1) << 1) - 1
}; /* enum so_state */


struct socket {
	struct so_options opts;
	struct dns_addrinfo *res;

	int fd;

	mode_t mode;  /* file mode */
	int domain;   /* socket domain (address family) */
	int type;     /* socket type */
	int protocol; /* socket protocol */
	int flags;    /* descriptor flags */

	struct so_stat st;

	struct {
		_Bool rd;
		_Bool wr;
	} shut;

	struct addrinfo *host;

	short events;

	int done, todo;

	int lerror;

	int olowat;

	struct {
		SSL *ctx;
		int error;
		int state;
		_Bool accept;
		_Bool vrfd;
	} ssl;

	struct {
		BIO *ctx;
//		BIO *ctrl; /* proxy unknown DTLS BIO_ctrl commands */
		int error;

		struct {
			void *data;
			unsigned char *p, *pe;
		} ahead;
	} bio;

	struct {
		int ncalls;
		sigset_t pending;
		sigset_t blocked;
	} pipeign;

	struct {
		pid_t pid;
		uid_t uid;
		gid_t gid;
	} cred;
}; /* struct socket */


static _Bool so_needign(struct socket *so, _Bool rdonly) {
	if (!so->opts.fd_nosigpipe || (so->flags & SO_F_NOSIGPIPE))
		return 0;
	if (so->ssl.ctx && !so->bio.ctx)
		return 1;
	if (rdonly)
		return 0;
#if defined MSG_NOSIGNAL
	if (S_ISSOCK(so->mode))
		return 0;
#endif
	return 1;
} /* so_needign() */


static int so_pipeign(struct socket *so, _Bool rdonly) {
	if (!so_needign(so, rdonly))
		return 0;

#if _POSIX_REALTIME_SIGNALS > 0
	if (so->pipeign.ncalls++ > 0)
		return 0;

	sigemptyset(&so->pipeign.pending);
	sigpending(&so->pipeign.pending);

	if (sigismember(&so->pipeign.pending, SIGPIPE))
		return 0;

	sigset_t piped;
	sigemptyset(&piped);
	sigaddset(&piped, SIGPIPE);
	sigemptyset(&so->pipeign.blocked);

	return thr_sigmask(SIG_BLOCK, &piped, &so->pipeign.blocked);
#else
	return EOPNOTSUPP;
#endif
} /* so_pipeign() */


static int so_pipeok(struct socket *so, _Bool rdonly) {
	if (!so_needign(so, rdonly))
		return 0;

#if _POSIX_REALTIME_SIGNALS > 0
	assert(so->pipeign.ncalls > 0);

	if (--so->pipeign.ncalls)
		return 0;

	if (sigismember(&so->pipeign.pending, SIGPIPE))
		return 0;

	sigset_t piped;
	sigemptyset(&piped);
	sigaddset(&piped, SIGPIPE);

	while (-1 == sigtimedwait(&piped, NULL, &(struct timespec){ 0, 0 }) && errno == EINTR)
		;;

	return thr_sigmask(SIG_SETMASK, &so->pipeign.blocked, NULL);
#else
	return EOPNOTSUPP;
#endif
} /* so_pipeok() */


static int so_getaddr_(struct socket *so) {
	int error;

	if (!so->res)
		return SO_ENOHOST;

	so->events = 0;

	free(so->host);
	so->host = 0;

	if ((error = dns_ai_nextent(&so->host, so->res)))
		goto error;

	return 0;
error:
	switch (error) {
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		so->events = dns_ai_events(so->res);

		break;
	} /* switch() */

	return error;
} /* so_getaddr_() */


static int so_socket_(struct socket *so) {
	int error;

	if (!so->host)
		return SO_ENOHOST;

	so_closesocket(&so->fd, &so->opts);

	if (-1 == (so->fd = so_socket(so->host->ai_family, so->host->ai_socktype, &so->opts, &error)))
		return error;

	if ((error = so_ftype(so->fd, &so->mode, &so->domain, &so->type, &so->protocol)))
		return error;

	so->flags = so_getfl(so->fd, ~0);

	return 0;
} /* so_socket_() */


static int so_bind_(struct socket *so) {
	struct sockaddr *saddr;

	if (so->todo & SO_S_LISTEN) {
		if (!so->host)
			return SO_ENOHOST;

		saddr = so->host->ai_addr;
	} else if (so->opts.sa_bind) {
		saddr = (struct sockaddr *)so->opts.sa_bind;
	} else {
		return 0;
	}

	return so_bind(so->fd, saddr, &so->opts);
} /* so_bind_() */


static int so_listen_(struct socket *so) {
	if (!S_ISSOCK(so->mode) || (so->type != SOCK_STREAM && so->type != SOCK_SEQPACKET))
		return 0;

	return (0 == listen(so->fd, SOMAXCONN))? 0 : so_soerr();
} /* so_listen_() */


static int so_connect_(struct socket *so) {
	int error;

	so->events &= ~POLLOUT;

retry:
	if (!so->host) {
		error = SO_ENOHOST;
		goto error;
	}

	if (0 != connect(so->fd, so->host->ai_addr, so->host->ai_addrlen)) {
		error = so_soerr();
		goto error;
	}

ready:
	so_trace(SO_T_CONNECT, so->fd, so->host, "ready");

	return 0;
error:
	switch (error) {
	case SO_EISCONN:
		goto ready;
	case SO_EINTR:
		goto retry;
	case SO_EINPROGRESS:
		/* FALL THROUGH */
	case SO_EALREADY:
		/* FALL THROUGH */
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK
		/* FALL THROUGH */
#endif
		so->events |= POLLOUT;

		return SO_EAGAIN;
	default:
		so_trace(SO_T_CONNECT, so->fd, so->host, "%s", so_strerror(error));

		return error;
	} /* switch() */
} /* so_connect_() */


static BIO *so_newbio(struct socket *, int *);

static int so_starttls_(struct socket *so) {
	X509 *peer;
	int rval, error;

	if (so->ssl.error)
		return so->ssl.error;

	so_pipeign(so, 0);

	ERR_clear_error();

	switch (so->ssl.state) {
	case 0: {
		/*
		 * NOTE: For SOCK_DGRAM continue using OpenSSL's BIO until
		 * we have time to reverse engineer the semantics necessary
		 * for DTLS.
		 */
		if (S_ISSOCK(so->mode) && so->type == SOCK_DGRAM) {
			struct sockaddr_storage peer;
			BIO *bio;

			memset(&peer, 0, sizeof peer);

			if (0 != getpeername(so->fd, (struct sockaddr *)&peer, &(socklen_t){ sizeof peer })) {
				error = errno;
				goto error;
			}

			if (!(bio = BIO_new_dgram(so->fd, BIO_NOCLOSE))) {
				error = SO_EOPENSSL;
				goto error;
			}

			BIO_ctrl_set_connected(bio, &peer);

			SSL_set_bio(so->ssl.ctx, bio, bio);
			SSL_set_read_ahead(so->ssl.ctx, 1);
		} else {
			BIO *bio;

			if (!(bio = so_newbio(so, &error)))
				goto error;

			SSL_set_bio(so->ssl.ctx, bio, bio);
		}

		if (so->ssl.accept) {
			SSL_set_accept_state(so->ssl.ctx);
		} else {
			SSL_set_connect_state(so->ssl.ctx);
		}

		so->ssl.state++;
	}
	case 1:
		rval = SSL_do_handshake(so->ssl.ctx);

		if (rval > 0) {
			/* SUCCESS (continue to next state) */
			;;
		} else {
			/* ERROR (either need I/O or a plain error) or SHUTDOWN */
			so->events &= ~(POLLIN|POLLOUT);

			error = ssl_error(so->ssl.ctx, rval, &so->events);

			goto error;
		} /* (rval) */

		so->ssl.state++;
	case 2:
		/*
		 * NOTE: Must call SSL_get_peer_certificate() first, which
		 * processes the certificate. SSL_get_verify_result() merely
		 * returns the result of this processing.
		 */
		peer = SSL_get_peer_certificate(so->ssl.ctx);
		so->ssl.vrfd = (peer && SSL_get_verify_result(so->ssl.ctx) == X509_V_OK);
		x509_discard(&peer);

		so->ssl.state++;
	case 3:
		if (so->opts.tls_verify && !so->ssl.vrfd) {
			error = SO_ENOTVRFD;

			goto error;
		}

		so->ssl.state++;
	case 4:
		break;
	} /* switch(so->ssl.state) */

#if SOCKET_DEBUG
	if (SOCKET_DEBUG) {
		const SSL_CIPHER *cipher = SSL_get_current_cipher(so->ssl.ctx);

		so_trace(SO_T_STARTTLS, so->fd, so->host, so->ssl.ctx,
			"%s-%s", SSL_get_version(so->ssl.ctx), SSL_CIPHER_get_name(cipher));
	}
#endif

	so_pipeok(so, 0);

	return 0;
error:
	if (error != SO_EAGAIN)
		so_trace(SO_T_STARTTLS, so->fd, so->host, so->ssl.ctx, "%s", so_strerror(error));

	so_pipeok(so, 0);

	return error;
} /* so_starttls_() */


static int so_rstlowat_(struct socket *so) {
	if (0 != setsockopt(so->fd, SOL_SOCKET, SO_RCVLOWAT, &so->olowat, sizeof so->olowat))
		return so_soerr();

	return 0;
} /* so_rstlowat_() */


static int so_shutwr_(struct socket *so) {
	if (so->fd != -1 && 0 != shutdown(so->fd, SHUT_WR))
		return so_soerr();

	so->shut.wr = 1;
	so->st.sent.eof = 1;

	return 0;
} /* so_shutwr_() */


static _Bool so_isconn(int fd) {
		struct sockaddr sa;
		socklen_t slen = sizeof sa;

		return 0 == getpeername(fd, &sa, &slen) || so_soerr() != SO_ENOTCONN;
} /* so_isconn() */

static int so_shutrd_(struct socket *so) {
	if (so->fd != -1 && 0 != shutdown(so->fd, SHUT_RD)) {
		/*
		 * NOTE: OS X will fail with ENOTCONN if the requested
		 * SHUT_RD or SHUT_WR flag is already set, including if the
		 * SHUT_RD flag is set from the peer sending eof. Other OSs
		 * just treat this as a noop and return successfully.
		 */
		if (so_soerr() != SO_ENOTCONN)
			return so_soerr();
		else if (!so_isconn(so->fd))
			return SO_ENOTCONN;
	}

	so->shut.rd = 1;

	return 0;
} /* so_shutrd_() */


static inline int so_state(const struct socket *so) {
	if (so->todo & ~so->done) {
		int i = 1;

		while (i < SO_S_END && !(i & (so->todo & ~so->done)))
			i <<= 1;

		return (i < SO_S_END)? i : 0;
	} else
		return 0;
} /* so_state() */


static int so_exec(struct socket *so) {
	int state, error_, error = 0;

exec:

	switch (state = so_state(so)) {
	case SO_S_INIT:
		break;
	case SO_S_GETADDR:
		switch ((error_ = so_getaddr_(so))) {
		case 0:
			break;
		case ENOENT:
			/* NOTE: Return the last error if possible. */
			if (error)
				error_ = error;
			else if (so->lerror)
				error_ = so->lerror;

			/* FALL THROUGH */
		default:
			error = error_;

			goto error;
		}

		so->done |= state;

		goto exec;
	case SO_S_SOCKET:
		if ((error = so_socket_(so)))
			goto retry;

		so->done |= state;

		goto exec;
	case SO_S_BIND:
		if ((error = so_bind_(so)))
			goto retry;

		so->done |= state;

		goto exec;
	case SO_S_LISTEN:
		if ((error = so_listen_(so)))
			return error;

		so->done |= state;

		goto exec;
	case SO_S_CONNECT:
		if ((error = so_connect_(so))) {
			switch (error) {
			case SO_EAGAIN:
				goto error;
			default:
				goto retry;
			} /* switch() */
		}

		so->done |= state;

		goto exec;
	case SO_S_STARTTLS:
		if ((error = so_starttls_(so)))
			goto error;

		so->done |= state;

		goto exec;
	case SO_S_SETREAD:
		so->events |= POLLIN;
		so->done   |= state;

		goto exec;
	case SO_S_SETWRITE:
		so->events |= POLLOUT;
		so->done   |= state;

		goto exec;
	case SO_S_RSTLOWAT:
		if ((error = so_rstlowat_(so)))
			goto error;

		so->todo &= ~state;

		goto exec;
	case SO_S_SHUTWR:
		if ((error = so_shutwr_(so)))
			goto error;

		so->done |= state;

		goto exec;
	case SO_S_SHUTRD:
		if ((error = so_shutrd_(so)))
			goto error;

		so->done |= state;

		goto exec;
	} /* so_exec() */

	return 0;
retry:
	/*
	 * Jump back to the SO_S_GETADDR iterator if enabled. Otherwise,
	 * this is a terminal error.
	 */
	if (so->todo & SO_S_GETADDR) {
		so->done = 0;
		so->lerror = error;

		goto exec;
	}

	/* FALL THROUGH */
error:
	return error;
} /* so_exec() */


static struct socket *so_make(const struct so_options *opts, int *error) {
	static const struct socket so_initializer = {
		.fd = -1,
		.domain = PF_UNSPEC,
		.cred = { (pid_t)-1, (uid_t)-1, (gid_t)-1, }
	};
	struct socket *so;
	size_t len;

	if (!(so = malloc(sizeof *so)))
		goto syerr;

	*so = so_initializer;
	so->opts = *opts;

	if (opts->sa_bind) {
		if (!(len = sa_len((void *)opts->sa_bind))) {
			*error = EAFNOSUPPORT;
			goto error;
		}

		if (!(so->opts.sa_bind = malloc(len)))
			goto syerr;

		memcpy((void *)so->opts.sa_bind, opts->sa_bind, len);
	}

	if (opts->tls_sendname && opts->tls_sendname != SO_OPTS_TLS_HOSTNAME) {
		if (!(so->opts.tls_sendname = strdup(opts->tls_sendname)))
			goto syerr;
	}

	return so;
syerr:
	*error = so_syerr();
error:
	if (so) {
		if (so->opts.tls_sendname != opts->tls_sendname)
			free((void *)so->opts.tls_sendname);

		if (so->opts.sa_bind != opts->sa_bind)
			free((void *)so->opts.sa_bind);

		free(so);
	}

	return NULL;
} /* so_make() */


static void so_resetssl(struct socket *);

static int so_destroy(struct socket *so) {
	so_resetssl(so);

	dns_ai_close(so->res);
	so->res = NULL;

	free(so->host);
	so->host = NULL;

	so_closesocket(&so->fd, &so->opts);

	so->events = 0;

	if (so->opts.tls_sendname && so->opts.tls_sendname != SO_OPTS_TLS_HOSTNAME) {
		free((void *)so->opts.tls_sendname);
		so->opts.tls_sendname = NULL;
	}

	free((void *)so->opts.sa_bind);
	so->opts.sa_bind = NULL;

	return 0;
} /* so_destroy() */


static _Bool sa_isnumeric(const char *host) {
	union sockaddr_any ip;

	return !!sa_pton(&ip, sizeof ip, host, NULL, NULL);
} /* sa_isnumeric() */


struct socket *(so_open)(const char *host, const char *port, int qtype, int domain, int type, const struct so_options *opts, int *error_) {
	_Bool isnumeric = sa_isnumeric(host);
	struct dns_resolver *res = NULL;
	struct addrinfo hints;
	struct socket *so;
	int error;

	if (!(so = so_make(opts, &error)))
		goto error;

	/*
	 * Copy host name as TLS server host name.
	 *
	 * NOTE: All the TLS RFCs (from RFC 3546 to RFC 6066)
	 * declare
	 *
	 *      Literal IPv4 and IPv6 addresses are not permitted in
	 *      "HostName".
	 *
	 * If the caller wants to send the IP address as the TLS
	 * server host name, they can set .tls_hostname explicitly.
	 */
	if (so->opts.tls_sendname == SO_OPTS_TLS_HOSTNAME && !isnumeric) {
		if (!(so->opts.tls_sendname = strdup(host)))
			goto syerr;
	}

	memset(&hints, 0, sizeof hints);

	hints.ai_flags    = AI_CANONNAME;
	hints.ai_family   = domain;
	hints.ai_socktype = type;

	if (isnumeric) {
		hints.ai_flags |= AI_NUMERICHOST;
	} else {
		struct dns_options *opts = dns_opts();

		opts->closefd.arg = so->opts.fd_close.arg;
		opts->closefd.cb = so->opts.fd_close.cb;

		if (!(res = dns_res_stub(opts, &error)))
			goto error;
	}

	if (!(so->res = dns_ai_open(host, port, qtype, &hints, res, &error)))
		goto error;

	so->todo = SO_S_GETADDR | SO_S_SOCKET | SO_S_BIND;

	dns_res_close(res);

	return so;
syerr:
	error = so_syerr();
error:
	dns_res_close(res);

	so_close(so);

	*error_ = error;

	return 0;
} /* so_open() */


struct socket *so_dial(const struct sockaddr *sa, int type, const struct so_options *opts, int *error_) {
	struct { struct addrinfo ai; struct sockaddr_storage ss; } *host;
	struct socket *so;
	int error;

	if (!(so = so_make(opts, &error)))
		goto error;

	if (!(host = malloc(sizeof *host)))
		goto syerr;

	memset(&host->ai, 0, sizeof host->ai);
	memcpy(&host->ss, sa, SO_MIN(af_len(sa->sa_family), sizeof host->ss));

	so->host = &host->ai;
	so->host->ai_family = sa->sa_family;
	so->host->ai_socktype = type;
	so->host->ai_protocol = 0;
	so->host->ai_addrlen = af_len(sa->sa_family);
	so->host->ai_addr = (struct sockaddr *)&host->ss;

	so->todo = SO_S_SOCKET | SO_S_BIND;

	return so;
syerr:
	error = so_syerr();
error:
	so_close(so);

	*error_ = error;

	return 0;
} /* so_dial() */


struct socket *so_fdopen(int fd, const struct so_options *opts, int *error_) {
	struct socket *so;
	int flags, mask, need, error;

	if (!(so = so_make(opts, &error)))
		goto error;

	if ((error = so_ftype(fd, &so->mode, &so->domain, &so->type, &so->protocol)))
		goto error;

	flags = so_opts2flags(opts, &mask);
	mask &= so_type2mask(so->mode, so->domain, so->type, so->protocol);
	need = ~(SO_F_NODELAY|SO_F_NOPUSH|SO_F_NOSIGPIPE|SO_F_OOBINLINE);

	if ((error = so_rstfl(fd, &so->flags, flags, mask, need)))
		goto error;

	so->fd = fd;

	return so;
error:
	so_close(so);

	*error_ = error;

	return 0;
} /* so_fdopen() */


int so_close(struct socket *so) {
	if (!so)
		return EINVAL;

	so_destroy(so);

	free(so);

	return 0;
} /* so_close() */


int so_family(struct socket *so, int *error_) {
	struct sockaddr_storage saddr;
	socklen_t slen = sizeof saddr;
	int error;

	if ((error = so_localaddr(so, (void *)&saddr, &slen)))
		{ *error_ = error; return AF_UNSPEC; }

	return *sa_family(&saddr);
} /* so_family() */


int so_localaddr(struct socket *so, void *saddr, socklen_t *slen) {
	int error;

	if ((so_state(so) < SO_S_STARTTLS) && (error = so_exec(so)))
		return error;

	if (0 != getsockname(so->fd, saddr, slen))
		return errno;

	return 0;
} /* so_localaddr() */


int so_remoteaddr(struct socket *so, void *saddr, socklen_t *slen) {
	int error;

	if ((so_state(so) < SO_S_STARTTLS) && (error = so_exec(so)))
		return error;

	if (0 != getpeername(so->fd, saddr, slen))
		return errno;

	return 0;
} /* so_remoteaddr() */


int so_connect(struct socket *so) {
	if (so->done & SO_S_CONNECT)
		return 0;

	so->todo |= SO_S_CONNECT;

	return so_exec(so);
} /* so_connect() */


int so_listen(struct socket *so) {
	if (so->done & SO_S_LISTEN)
		return 0;

	so->todo |= SO_S_LISTEN;

	return so_exec(so);
} /* so_listen() */


int so_accept(struct socket *so, struct sockaddr *saddr, socklen_t *slen, int *error_) {
	int fd = -1, error;

	if ((error = so_listen(so)))
		goto error;

	if ((error = so_exec(so)))
		goto error;

	so->events = POLLIN;

retry:
#if HAVE_ACCEPT4 && defined SOCK_CLOEXEC
	if (-1 == (fd = accept4(so->fd, saddr, slen, SOCK_CLOEXEC)))
		goto soerr;
#elif HAVE_PACCEPT && defined SOCK_CLOEXEC
	if (-1 == (fd = paccept(so->fd, saddr, slen, NULL, SOCK_CLOEXEC)))
		goto soerr;
#else
	if (-1 == (fd = accept(so->fd, saddr, slen)))
		goto soerr;

	if ((error = so_cloexec(fd, 1)))
		goto error;
#endif

	return fd;
soerr:
	switch ((error = so_soerr())) {
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		error = SO_EAGAIN;

		break;
#endif
	case SO_ECONNABORTED:
		error = SO_EAGAIN;

		break;
	}
error:
	*error_ = error;

	so_closesocket(&fd, NULL);

	return -1;
} /* so_accept() */


static void so_resetssl(struct socket *so) {
	ssl_discard(&so->ssl.ctx);
	so->ssl.state  = 0;
	so->ssl.error  = 0;
	so->ssl.accept = 0;
	so->ssl.vrfd   = 0;

	if (so->bio.ctx) {
		BIO_free(so->bio.ctx);
		so->bio.ctx = NULL;
	}

	free(so->bio.ahead.data);
	so->bio.ahead.data = NULL;
	so->bio.ahead.p = NULL;
	so->bio.ahead.pe = NULL;
} /* so_resetssl() */

int so_starttls(struct socket *so, const struct so_starttls *cfg) {
	SSL_CTX *ctx, *tmp = NULL;
	SSL *ssl = NULL;
	const SSL_METHOD *method;
	int error;

	if (so->done & SO_S_STARTTLS)
		return 0;

	if (so->todo & SO_S_STARTTLS)
		goto check;

	cfg = (cfg)? cfg : &(struct so_starttls){ 0 };

	so_resetssl(so);

	/*
	 * NOTE: Commit to the SO_S_STARTTLS state at this point, no matter
	 * whether we can allocate the proper objects, so any errors will
	 * persist. so_starttls_() immediately returns if so->ssl.error is
	 * set. See NOTE at error label below.
	 */
	so->todo |= SO_S_STARTTLS;

	if (cfg->pushback.iov_len > 0) {
		if (!(so->bio.ahead.data = malloc(cfg->pushback.iov_len))) {
			error = errno;
			goto error;
		}

		memcpy(so->bio.ahead.data, cfg->pushback.iov_base, cfg->pushback.iov_len);
		so->bio.ahead.p = so->bio.ahead.data;
		so->bio.ahead.pe = so->bio.ahead.p + cfg->pushback.iov_len;
	}

	ERR_clear_error();

	if ((ssl = cfg->instance)) {
		SSL_up_ref(ssl);
	} else {
		if (!(ctx = cfg->context)) {
			if (!(method = cfg->method)) {
				if (so_isbool(cfg->accept)) {
					method = SSLv23_method();
				} else {
					method = SSLv23_client_method();
				}
			}

			if (!(ctx = tmp = SSL_CTX_new((SSL_METHOD *)method)))
				goto eossl;
		}

		if (!(ssl = SSL_new(ctx)))
			goto eossl;
	}

	if (so_isbool(cfg->accept)) {
		so->ssl.accept = so_tobool(cfg->accept);
	} else {
		/* NB: see WARNING at compat_SSL_is_server() */
		so->ssl.accept = SSL_is_server(ssl);
	}

	if (!so->ssl.accept && so->opts.tls_sendname && so->opts.tls_sendname != SO_OPTS_TLS_HOSTNAME) {
		if (!SSL_set_tlsext_host_name(ssl, so->opts.tls_sendname))
			goto eossl;
	}

	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);

	so->ssl.ctx = ssl;
	ssl = NULL;

	if (tmp)
		SSL_CTX_free(tmp);

check:
	return so_exec(so);
eossl:
	error = SO_EOPENSSL;
error:
	/*
	 * NOTE: Store any error in so->ssl.error because callers expect to
	 * call-and-forget this routine, similar to so_connect() and
	 * so_listen(), but we still need to replay the error.
	 */
	so->ssl.error = error;

	if (ssl)
		SSL_free(ssl);

	if (tmp)
		SSL_CTX_free(tmp);

	return so->ssl.error;
} /* so_starttls() */


SSL *so_checktls(struct socket *so) {
	return so->ssl.ctx;
} /* so_checktls() */


int so_shutdown(struct socket *so, int how) {
	switch (how) {
	case SHUT_RD:
		so->todo |= SO_S_SHUTRD;

		break;
	case SHUT_WR:
		so->todo |= SO_S_SHUTWR;

		break;
	case SHUT_RDWR:
		so->todo |= SO_S_SHUTRD|SO_S_SHUTWR;

		break;
	} /* switch (how) */

	return so_exec(so);
} /* so_shutdown() */


static size_t so_sysread(struct socket *so, void *dst, size_t lim, int *error) {
	long len;

retry:
#if _WIN32
	len = recv(so->fd, dst, SO_MIN(lim, LONG_MAX), 0);
#else
	len = read(so->fd, dst, SO_MIN(lim, LONG_MAX));
#endif

	if (len == -1)
		goto error;
	if (len == 0)
		goto epipe;

	return len;
epipe:
	*error = EPIPE;
	so->st.rcvd.eof = 1;

	return 0;
error:
	*error = so_soerr();

	switch (*error) {
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		*error = SO_EAGAIN;
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		so->events |= POLLIN;
		break;
	} /* switch() */

	return 0;
} /* so_sysread() */

static size_t so_syswrite(struct socket *so, const void *src, size_t len, int *error) {
	long count;
	int flags = 0;

	if (so->st.sent.eof) {
		*error = EPIPE;
		return 0;
	}

//	so_pipeign(so, 0);

#if _WIN32
#else
	if (S_ISSOCK(so->mode)) {
		#if defined(MSG_NOSIGNAL)
		if (so->opts.fd_nosigpipe)
			flags |= MSG_NOSIGNAL;
		#endif
		if (so->type == SOCK_SEQPACKET)
			flags |= MSG_EOR;
	}
#endif
retry:
#if _WIN32
	if (1) {
#else
	if (S_ISSOCK(so->mode)) {
#endif
		count = send(so->fd, src, SO_MIN(len, LONG_MAX), flags);
	} else {
		count = write(so->fd, src, SO_MIN(len, LONG_MAX));
	}

	if (count == -1)
		goto error;

//	so_pipeok(so, 0);

	return count;
error:
	*error = so_soerr();

	switch (*error) {
	case EPIPE:
		so->st.sent.eof = 1;
		break;
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		*error = SO_EAGAIN;
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		so->events |= POLLOUT;
		break;
	} /* switch() */

//	so_pipeok(so, 0);

	return 0;
} /* so_syswrite() */


static _Bool bio_nonfatal(int error) {
	switch (error) {
	case SO_EAGAIN:
	case SO_EALREADY:
	case SO_EINPROGRESS:
	case SO_EINTR:
	case SO_ENOTCONN: /* FIXME (bss_sock.c has this but is it correct?) */
		return 1;
	default:
		return 0;
	}
} /* bio_nonfatal() */

static int bio_read(BIO *bio, char *dst, int lim) {
	struct socket *so = BIO_get_data(bio);
	size_t count;

	assert(so);
	assert(lim >= 0);

	BIO_clear_retry_flags(bio);
	so->bio.error = 0;

	if (so->bio.ahead.p < so->bio.ahead.pe) {
		count = SO_MIN(so->bio.ahead.pe - so->bio.ahead.p, lim);
		memcpy(dst, so->bio.ahead.p, count);
		so->bio.ahead.p += count;

		return count;
	}

	if ((count = so_sysread(so, dst, lim, &so->bio.error)))
		return (int)count;

	if (bio_nonfatal(so->bio.error))
		BIO_set_retry_read(bio);

	/* see note about SSL_ERROR_SYSCALL at bio_write */
	errno = so->bio.error;

	return (so->bio.error == EPIPE)? 0 : -1;
} /* bio_read() */

static int bio_write(BIO *bio, const char *src, int len) {
	struct socket *so = BIO_get_data(bio);
	size_t count;

	assert(so);
	assert(len >= 0);

	BIO_clear_retry_flags(bio);
	so->bio.error = 0;

	if ((count = so_syswrite(so, src, len, &so->bio.error)))
		return (int)count;

	if (bio_nonfatal(so->bio.error))
		BIO_set_retry_write(bio);

	/*
	 * SSL_get_error will return SSL_ERROR_SYSCALL, expecting errno to
	 * be set.
	 */
	errno = so->bio.error;

	return -1;
} /* bio_write() */

static int bio_puts(BIO *bio, const char *src) {
	size_t len = strlen(src);

	return bio_write(bio, src, (int)SO_MIN(len, INT_MAX));
} /* bio_puts() */

static long bio_ctrl(BIO *bio, int cmd, long udata_i, void *udata_p) {
	(void)bio;
	(void)udata_i;

	switch (cmd) {
	case BIO_CTRL_DUP: {
		/*
		 * We'll permit duping, just like all the other BIOs do by
		 * default and so we don't inadvertently break something.
		 * But we won't copy our state because our memory management
		 * assumes 1:1 mapping between BIO and socket objects. And
		 * just to be safe, zero the state members. BIO_dup_chain,
		 * for example, has a hack to always copy .init and .num.
		 */
		BIO *udata = udata_p;
		BIO_set_init(udata, 0);
		BIO_set_data(udata, NULL);

		return 1;
	}
	case BIO_CTRL_FLUSH:
		return 1;
	default:
		/*
		 * BIO_ctrl manual page says
		 *
		 * 	Source/sink BIOs return an 0 if they do not
		 * 	recognize the BIO_ctrl() operation.
		 */
		return 0;
	} /* switch() */
} /* bio_ctrl() */

static int bio_create(BIO *bio) {
	BIO_set_init(bio, 0);
	BIO_set_shutdown(bio, 0);
	BIO_set_data(bio, NULL);

	return 1;
} /* bio_create() */

static int bio_destroy(BIO *bio) {
	BIO_set_init(bio, 0);
	BIO_set_shutdown(bio, 0);
	BIO_set_data(bio, NULL);

	return 1;
} /* bio_destroy() */

#if !HAVE_OPENSSL11_API
static BIO_METHOD bio_methods = {
	BIO_TYPE_SOURCE_SINK,
	"struct socket*",
	bio_write,
	bio_read,
	bio_puts,
	NULL,
	bio_ctrl,
	bio_create,
	bio_destroy,
	NULL,
};

static BIO_METHOD *so_get_bio_methods() {
	return &bio_methods;
} /* so_get_bio_methods() */
#else
static BIO_METHOD *bio_methods = NULL;

static CRYPTO_ONCE bio_methods_init_once = CRYPTO_ONCE_STATIC_INIT;

static void bio_methods_init(void) {
	int type = BIO_get_new_index();
	if (type == -1)
		return;

	bio_methods = BIO_meth_new(type|BIO_TYPE_SOURCE_SINK, "struct socket*");
	if (bio_methods == NULL)
		return;

	BIO_meth_set_write(bio_methods, bio_write);
	BIO_meth_set_read(bio_methods, bio_read);
	BIO_meth_set_puts(bio_methods, bio_puts);
	BIO_meth_set_ctrl(bio_methods, bio_ctrl);
	BIO_meth_set_create(bio_methods, bio_create);
	BIO_meth_set_destroy(bio_methods, bio_destroy);
} /* bio_methods_init() */

static BIO_METHOD *so_get_bio_methods() {
	if (bio_methods == NULL) {
		CRYPTO_THREAD_run_once(&bio_methods_init_once, bio_methods_init);
	}
	return bio_methods;
} /* so_get_bio_methods() */
#endif

static BIO *so_newbio(struct socket *so, int *error) {
	BIO *bio;
	BIO_METHOD *bio_methods = so_get_bio_methods();

	if (bio_methods == NULL || !(bio = BIO_new(bio_methods))) {
		*error = SO_EOPENSSL;
		return NULL;
	}

	BIO_set_init(bio, 1);
	BIO_set_data(bio, so);

	/*
	 * NOTE: Applications can acquire a reference to our BIO via the SSL
	 * state object. The lifetime of the BIO could last longer than the
	 * lifetime of our socket object, so we must keep our own reference
	 * and zero any pointer to ourselves here and from so_destroy.
	 */
	if (so->bio.ctx) {
		BIO_set_init(so->bio.ctx, 0);
		BIO_set_data(so->bio.ctx, NULL);
		BIO_free(so->bio.ctx);
	}

	BIO_up_ref(bio);
	so->bio.ctx = bio;

	return bio;
} /* so_newbio() */


size_t so_read(struct socket *so, void *dst, size_t lim, int *error_) {
	size_t len;
	int error;

	so_pipeign(so, 1);

	so->todo |= SO_S_SETREAD;

	if ((error = so_exec(so)))
		goto error;

	if (so->fd == -1) {
		error = ENOTCONN;
		goto error;
	}

	so->events &= ~POLLIN;
retry:
	if (so->ssl.ctx) {
		int n;

		ERR_clear_error();

		if ((n = SSL_read(so->ssl.ctx, dst, SO_MIN(lim, INT_MAX))) < 0) {
			if (SO_EINTR == (error = ssl_error(so->ssl.ctx, n, &so->events)))
				goto retry;
			goto error;
		} else if (n == 0) {
			error = EPIPE; /* FIXME: differentiate clean from unclean shutdown? */
			so->st.rcvd.eof = 1;
			goto error;
		}

		len = n;
	} else {
		if (!(len = so_sysread(so, dst, lim, &error)))
			goto error;
	}

	so_trace(SO_T_READ, so->fd, so->host, dst, (size_t)len, "rcvd %zu bytes", (size_t)len);
	st_update(&so->st.rcvd, len, &so->opts);

	so_pipeok(so, 1);

	return len;
error:
	*error_ = error;

	if (error != SO_EAGAIN)
		so_trace(SO_T_READ, so->fd, so->host, (void *)0, (size_t)0, "%s", so_strerror(error));

	so_pipeok(so, 1);

	return 0;
} /* so_read() */


size_t so_write(struct socket *so, const void *src, size_t len, int *error_) {
	size_t count;
	int error;

	so_pipeign(so, 0);

	so->todo |= SO_S_SETWRITE;

	if ((error = so_exec(so)))
		goto error;

	if (so->fd == -1) {
		error = ENOTCONN;
		goto error;
	}

	so->events &= ~POLLOUT;
retry:
	if (so->ssl.ctx) {
		if (len > 0) {
			int n;

			ERR_clear_error();

			if ((n = SSL_write(so->ssl.ctx, src, SO_MIN(len, INT_MAX))) < 0) {
				if (SO_EINTR == (error = ssl_error(so->ssl.ctx, n, &so->events)))
					goto retry;
				goto error;
			} else if (n == 0) {
				error = EPIPE; /* FIXME: differentiate clean from unclean shutdown? */
				so->st.sent.eof = 1;
				goto error;
			}

			count = n;
		} else {
			count = 0;
		}
	} else {
		if (!(count = so_syswrite(so, src, len, &error)))
			goto error;
	}

	so_trace(SO_T_WRITE, so->fd, so->host, src, (size_t)count, "sent %zu bytes", (size_t)count);
	st_update(&so->st.sent, count, &so->opts);

	so_pipeok(so, 0);

	return count;
error:
	*error_ = error;

	if (error != SO_EAGAIN)
		so_trace(SO_T_WRITE, so->fd, so->host, (void *)0, (size_t)0, "%s", so_strerror(error));

	so_pipeok(so, 0);

	return 0;
} /* so_write() */


size_t so_peek(struct socket *so, void *dst, size_t lim, int flags, int *_error) {
	int rstlowat = so->todo & SO_S_RSTLOWAT;
	long count;
	int lowat, error;

	so->todo &= ~SO_S_RSTLOWAT;

	error = so_exec(so);

	so->todo |= rstlowat;

	if (error)
		goto error;

	if (flags & SO_F_PEEKALL)
		so->events &= ~POLLIN;
retry:
	count = recv(so->fd, dst, lim, MSG_PEEK);

	if (count == -1)
		goto soerr;

	if ((size_t)count == lim || !(flags & SO_F_PEEKALL))
		return count;
pollin:
	if (!(so->todo & SO_S_RSTLOWAT)) {
		if (0 != getsockopt(so->fd, SOL_SOCKET, SO_RCVLOWAT, &so->olowat, &(socklen_t){ sizeof so->olowat }))
			goto soerr;

		if (lim > INT_MAX) {
			error = EOVERFLOW;

			goto error;
		}

		lowat = (int)lim;

		if (0 != setsockopt(so->fd, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof lowat))
			goto soerr;

		so->todo |= SO_S_RSTLOWAT;
	}

	so->events |= POLLIN;

	*_error = SO_EAGAIN;

	return 0;
soerr:
	error = so_soerr();

	switch (error) {
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		if (flags & SO_F_PEEKALL)
			goto pollin;

		break;
	} /* switch() */
error:
	*_error = error;

	return 0;
} /* so_peek() */


int so_sendmsg(struct socket *so, const struct msghdr *msg, int flags) {
	ssize_t count;
	int error;

	so_pipeign(so, 0);

	so->todo |= SO_S_SETWRITE;

	if ((error = so_exec(so)))
		goto error;

	so->events &= ~POLLOUT;

#if defined MSG_NOSIGNAL
	if (so->opts.fd_nosigpipe)
		flags |= MSG_NOSIGNAL;
#endif

retry:
	if (-1 == (count = sendmsg(so->fd, msg, flags)))
		goto syerr;

	st_update(&so->st.sent, count, &so->opts);

	so_pipeok(so, 0);

	return 0;
syerr:
	error = errno;
error:
	switch (error) {
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		so->events |= POLLOUT;

		break;
	} /* switch() */

	so_pipeok(so, 0);

	return error;
} /* so_sendmsg() */


int so_recvmsg(struct socket *so, struct msghdr *msg, int flags) {
	ssize_t count;
	int error;

	so_pipeign(so, 1);

	so->todo |= SO_S_SETREAD;

	if ((error = so_exec(so)))
		goto error;

	so->events &= ~POLLIN;
retry:
	if (-1 == (count = recvmsg(so->fd, msg, flags))) {
		goto syerr;
	} else if (!count) {
		so->st.rcvd.eof = 1;
		error = EPIPE;
		goto error;
	}

	st_update(&so->st.rcvd, count, &so->opts);

	/* RE .msg_iovlen type
	 *
	 * 	- Linux    : size_t
	 * 	- OS X     : int
	 * 	- OpenBSD  : unsigned int
	 * 	- Solaris  : int
	 * 	- FreeBSD  : int
	 * 	- NetBSD   : int
	 * 	- RFC 2292 : size_t
	 */
	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		if ((size_t)count < msg->msg_iov[i].iov_len) {
			msg->msg_iov[i].iov_len = count;

			break;
		} else {
			count -= (ssize_t)msg->msg_iov[i].iov_len;
		}
	}

	so_pipeok(so, 1);

	return 0;
syerr:
	error = errno;
error:
	switch (error) {
	case SO_EINTR:
		goto retry;
#if SO_EWOULDBLOCK != SO_EAGAIN
	case SO_EWOULDBLOCK:
		/* FALL THROUGH */
#endif
	case SO_EAGAIN:
		so->events |= POLLIN;

		break;
	} /* switch() */

	so_pipeok(so, 1);

	return error;
} /* so_recvmsg() */


const struct so_stat *so_stat(struct socket *so) {
	return &so->st;
} /* so_stat() */


void so_clear(struct socket *so) {
	so->todo   &= ~(SO_S_SETREAD|SO_S_SETWRITE);
	so->events = 0;
} /* so_clear() */


int so_events(struct socket *so) {
	short events;

	switch (so->opts.fd_events) {
	case SO_LIBEVENT:
		events = SO_POLL2EV(so->events);

		break;
	default:
		/* FALL THROUGH */
	case SO_SYSPOLL:
		events = so->events;

		break;
	} /* switch (.fd_events) */

	return events;
} /* so_events() */


int so_pollfd(struct socket *so) {
	switch (so_state(so)) {
	case SO_S_GETADDR:
		return dns_ai_pollfd(so->res);
	default:
		return so->fd;
	} /* switch() */
} /* so_pollfd() */


int so_poll(struct socket *so, int timeout) {
	int nfds;

#if 1
	struct pollfd pfd = { .fd = so_pollfd(so), .events = so->events, };

	if (!pfd.events)
		return 0;

	if (timeout != -1)
		timeout *= 1000;

	nfds = poll(&pfd, 1, timeout);
#else
	fd_set rfds, wfds;
	int set, fd;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	if (!(set = so->events))
		return 0;

	fd = so_pollfd(so);

	if ((set & POLLIN) && fd < FD_SETSIZE)
		FD_SET(fd, &rfds);

	if ((set & POLLOUT) && fd < FD_SETSIZE)
		FD_SET(fd, &wfds);

	nfds = select(fd + 1, &rfds, &wfds, 0, (timeout >= 0)? &(struct timeval){ timeout, 0 } : 0);
#endif

	switch (nfds) {
	case -1:
		return errno;
	case 0:
		return ETIMEDOUT;
	default:
		return 0;
	}
} /* so_poll() */


int so_peerfd(struct socket *so) {
	return so->fd;
} /* so_peerfd() */


int so_uncork(struct socket *so) {
	return so_nopush(so->fd, 0);
} /* so_uncork() */


static int so_loadcred(struct socket *so) {
	if (so->cred.uid != (uid_t)-1)
		return 0;

#if defined SO_PEERCRED
#if defined __OpenBSD__
	struct sockpeercred uc;
#else
	struct ucred uc;
#endif

	if (0 != getsockopt(so->fd, SOL_SOCKET, SO_PEERCRED, &uc, &(socklen_t){ sizeof uc }))
		return errno;

	so->cred.pid = uc.pid;
	so->cred.uid = uc.uid;
	so->cred.gid = uc.gid;

	return 0;
#elif defined LOCAL_PEEREID
	struct unpcbid unp = { -1, -1, -1 };

	if (0 != getsockopt(so->fd, 0, LOCAL_PEEREID, &unp, &(socklen_t){ sizeof unp }))
		return errno;

	so->cred.pid = unp.unp_pid;
	so->cred.uid = unp.unp_euid;
	so->cred.gid = unp.unp_egid;

	return 0;
#elif defined __sun
	ucred_t *uc = NULL;

	if (0 != getpeerucred(so->fd, &uc))
		return errno;

	so->cred.pid = ucred_getpid(uc);
	so->cred.uid = ucred_geteuid(uc);
	so->cred.gid = ucred_getegid(uc);

	ucred_free(uc);

	return 0;
#else
	if (0 != getpeereid(so->fd, &so->cred.uid, &so->cred.gid))
		return errno;

	return 0;
#endif
} /* so_loadcred() */


int so_peereid(struct socket *so, uid_t *uid, gid_t *gid) {
	int error;

	if ((error = so_loadcred(so)))
		return error;

	if (so->cred.uid == (uid_t)-1)
		return EOPNOTSUPP;

	if (uid)
		*uid = so->cred.uid;
	if (gid)
		*gid = so->cred.gid;

	return 0;
} /* so_peereid() */


int so_peerpid(struct socket *so, pid_t *pid) {
	int error;

	if ((error = so_loadcred(so)))
		return error;

	if (so->cred.pid == (pid_t)-1)
		return EOPNOTSUPP;

	if (pid)
		*pid = so->cred.pid;

	return 0;
} /* so_peerpid() */


/*
 * L I B R A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void socket_init(void) __attribute__((constructor, used));

void socket_init(void) {
	SSL_load_error_strings();
	SSL_library_init();

	so_initdebug();
} /* socket_init() */



#if SOCKET_MAIN

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <err.h>

#include <regex.h>

#include "fifo.h"


struct {
	char arg0[64];

	struct {
		char scheme[32];
		char authority[128];
		char host[128];
		char port[32];
		char path[128];
		char query[64];
		char fragment[32];
	} url;
} MAIN = {
	.url = {
		.scheme = "http",
		.host   = "google.com",
		.port   = "80",
		.path   = "/",
	},
};


static void panic(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);

#if _WIN32
	vfprintf(stderr, fmt, ap);

	exit(EXIT_FAILURE);
#else
	verrx(EXIT_FAILURE, fmt, ap);
#endif
} /* panic() */

#define panic_(fn, ln, fmt, ...)	\
	panic(fmt "%0s", (fn), (ln), __VA_ARGS__)
#define panic(...)			\
	panic_(__func__, __LINE__, "(%s:%d) " __VA_ARGS__, "")


void parseurl(const char *url) {
	static const char *expr = "^(([^:/?#]+):)?(//(([^/@]*@)?([^/?#:]*)(:([[:digit:]]*))?))?([^?#]*)(\\?([^#]*))?(#(.*))?";
	regex_t re;
	regmatch_t match[16];
	char errstr[128];
	int error;
	struct { const char *name; char *dst; size_t lim; } part[16] = {
		[2]  = { "scheme:   ", MAIN.url.scheme,    sizeof MAIN.url.scheme },
		[4]  = { "authority:", MAIN.url.authority, sizeof MAIN.url.authority },
		[6]  = { "host:     ", MAIN.url.host,      sizeof MAIN.url.host },
		[8]  = { "port:     ", MAIN.url.port,      sizeof MAIN.url.port },
		[9]  = { "path:     ", MAIN.url.path,      sizeof MAIN.url.path },
		[11] = { "query:    ", MAIN.url.query,     sizeof MAIN.url.query },
		[13] = { "fragment: ", MAIN.url.fragment,  sizeof MAIN.url.fragment },
	};

	if ((error = regcomp(&re, expr, REG_EXTENDED)))
		goto error;

	if ((error = regexec(&re, url, countof(match), match, 0)))
		goto error;

	for (size_t i = 0; i < countof(match); i++) {
		if (match[i].rm_so == -1)
			continue;

		if (part[i].dst) {
			snprintf(part[i].dst, part[i].lim, "%.*s", (int)(match[i].rm_eo - match[i].rm_so), &url[match[i].rm_so]);
//			SAY("%s %s", part[i].name, part[i].dst);
		} else {
//			SAY("[%d]:       %.*s", i, (int)(match[i].rm_eo - match[i].rm_so), &url[match[i].rm_so]);
			;;
		}
	}

	regfree(&re);

	return;
error:
	regerror(error, &re, errstr, sizeof errstr);
	regfree(&re);

	panic("%s", errstr);
} /* parseurl() */


int httpget(const char *url) {
	const struct so_stat *st;
	struct socket *so;
	struct fifo *req;
	struct iovec iov;
	long n;
	int lc, error;

	parseurl(url);

	if (!(so = so_open(MAIN.url.host, MAIN.url.port, DNS_T_A, PF_INET, SOCK_STREAM, so_opts(), &error)))
		errx(EXIT_FAILURE, "so_open: %s", so_strerror(error));

	so_connect(so);

	if (!strcasecmp("https", MAIN.url.scheme)) {
		SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

#if 0 /* example code if waiting for SSL negotiation */
		while ((error = so_starttls(so, ctx))) {
			if (error != SO_EAGAIN || (error = so_poll(so, 3)))
				errx(EXIT_FAILURE, "so_starttls: %s", so_strerror(error));
		}
#else
		so_starttls(so, &(struct so_starttls){ .context = ctx });
#endif
	}

	req = fifo_new(1024);

	fifo_puts(req, "GET ");
	fifo_puts(req, MAIN.url.path);
	fifo_puts(req, " HTTP/1.0\r\n");
	fifo_puts(req, "Host: ");
	fifo_puts(req, MAIN.url.host);
	fifo_putc(req, ':');
	fifo_puts(req, MAIN.url.port);
	fifo_puts(req, "\r\n\r\n");

	while (fifo_rvec(req, &iov)) {
		if (!(n = so_write(so, iov.iov_base, iov.iov_len, &error))) {
			switch (error) {
			case SO_EAGAIN:
				so_poll(so, 1);

				break;
			default:
				errx(EXIT_FAILURE, "so_write: %s", so_strerror(error));
			}
		} else {
			fifo_discard(req, n);
		}
	}

//	so_shutdown(so, SHUT_WR); /* send EOF (but some servers don't like this) */

	lc = 0;

	do {
		char res[512];

		while (0 == (n = so_read(so, res, sizeof res, &error)) && error != EPIPE) {
			switch (error) {
			case SO_EAGAIN:
				so_poll(so, 1);

				continue;
			default:
				errx(EXIT_FAILURE, "so_read: %s", so_strerror(error));
			}
		}

		if (n > 0) {
			fwrite(res, 1, n, stdout);
			lc = res[n-1];
		}
	} while (n);

	if (isatty(STDOUT_FILENO) && isatty(STDERR_FILENO)) {
		if (lc != '\n')
			fputc('\n', stdout);

		fflush(stdout);

		fputs("--\n", stderr);
	}

	st = so_stat(so);

	fprintf(stderr, "sent: %llu bytes\n", st->sent.count);
	fprintf(stderr, "rcvd: %llu bytes\n", st->rcvd.count);

	so_close(so);

	return 0;
} /* httpget() */


int echo(void) {
	struct socket *srv0, *srv, *cli;
	struct fifo out, in;
	char obuf[512], ibuf[512];
	size_t olen, len;
	struct iovec iov;
	int fd, error;

	if (!(srv0 = so_open("127.0.0.1", "54321", DNS_T_A, PF_INET, SOCK_STREAM, so_opts(), &error)))
		panic("so_open: %s", so_strerror(error));

	if (!(cli = so_open("127.0.0.1", "54321", DNS_T_A, PF_UNSPEC, SOCK_STREAM, so_opts(), &error)))
		panic("so_open: %s", so_strerror(error));

	so_listen(srv0);

	while (-1 == (fd = so_accept(srv0, 0, 0, &error))) {
		if (error != SO_EAGAIN)
			panic("so_accept: %s", so_strerror(error));

		if ((error = so_connect(cli)) && error != SO_EAGAIN)
			panic("so_connect: %s", so_strerror(error));

		so_poll(cli, 1);
	}

	if (!(srv = so_fdopen(fd, so_opts(), &error)))
		panic("so_fdopen: %s", so_strerror(error));

	while ((olen = fread(obuf, 1, sizeof obuf, stdin))) {
		fifo_from(&out, obuf, olen);
		fifo_init(&in, ibuf, sizeof ibuf);

		while (fifo_rlen(&in) < olen) {
			if (fifo_rvec(&out, &iov)) {
				so_poll(cli, 1);

				if (!(len = so_write(cli, iov.iov_base, iov.iov_len, &error)) && error != SO_EAGAIN)
					panic("so_write: %s", so_strerror(error));
				else
					fifo_discard(&out, len);
			}

			so_poll(srv, 1);

			fifo_wvec(&in, &iov);

			if (!(len = so_read(srv, iov.iov_base, iov.iov_len, &error)) && error != SO_EAGAIN && error != EPIPE)
				panic("so_read: %s", so_strerror(error));
			else
				fifo_update(&in, +len);
		}

		while (fifo_rvec(&in, &iov))
			fifo_discard(&in, fwrite(iov.iov_base, 1, iov.iov_len, stdout));
	}

	so_close(srv0);
	so_close(srv);
	so_close(cli);

	return 0;
} /* echo() */


#define USAGE \
	"%s [-h] echo | egress ADDR [PORT] | print ADDR [PORT] | get URI\n" \
	"  -v  be verbose--trace input/output\n" \
	"  -V  print version information\n" \
	"  -h  print usage information\n" \
	"\n" \
	"Report bugs to william@25thandClement.com\n"

int main(int argc, char **argv) {
	extern int optind;
	int opt;

	dns_strlcpy(MAIN.arg0, (strrchr(argv[0], '/')? strrchr(argv[0], '/') + 1 : argv[0]), sizeof MAIN.arg0);

	while (-1 != (opt = getopt(argc, argv, "vVh"))) {
		switch (opt) {
		case 'v':
#if !defined(so_trace) /* macro expanding to void statement if no debug support */
			socket_debug++;
#else
			fprintf(stderr, "%s: not compiled with tracing support\n", MAIN.arg0);
#endif

			break;
		case 'V':
			printf("%s (socket.c) %.8X\n", MAIN.arg0, socket_v_rel());
			printf("vendor  %s\n", socket_vendor());
			printf("release %.8X\n", socket_v_rel());
			printf("abi     %.8X\n", socket_v_abi());
			printf("api     %.8X\n", socket_v_api());
			printf("dns     %.8X\n", dns_v_rel());
			printf("ssl     %s\n", OPENSSL_VERSION_TEXT);

			return 0;
		case 'h':
			/* FALL THROUGH */
usage:		default:
			fprintf(stderr, USAGE, MAIN.arg0);

			return (opt == 'h')? 0: EXIT_FAILURE;
		} /* switch() */
	} /* while () */

	argc -= optind;
	argv += optind;

	socket_init();

	if (!argc) {
		goto usage;
	} else if (!strcmp(*argv, "echo")) {
		return echo();
	} else if (!strcmp(*argv, "egress") && argv[1]) {
		struct sockaddr *saddr;
		struct sockaddr_storage egress;
		int error;

		if (AF_UNSPEC == *sa_family(saddr = sa_aton(argv[1]))) {
			struct dns_resolver *res;
			struct dns_packet *ans;
			struct dns_rr rr;
			union dns_any rd;
			char addr[SA_ADDRSTRLEN];

			if (!(res = dns_res_stub(dns_opts(), &error)))
				panic("dns_res_stub: %s", so_strerror(error));

			if (!(ans = dns_res_query(res, argv[1], DNS_T_A, DNS_C_IN, 1, &error)))
				panic("dns_res_query: %s", so_strerror(error));

			dns_res_close(res);

			if (!dns_rr_grep(&rr, 1, dns_rr_i_new(ans, .section = DNS_S_AN, .type = DNS_T_A), ans, &error))
				panic("%s: no A record", argv[1]);

			if ((error = dns_any_parse(&rd, &rr, ans)))
				panic("%s: %s", argv[1], so_strerror(error));

			dns_any_print(addr, sizeof addr, &rd, rr.type);

			free(ans);

			saddr = sa_aton(addr);

			if (AF_UNSPEC == sa_family(saddr))
				goto usage;
		}

		if (argc > 2) {
			*sa_port(saddr, SA_PORT_NONE, NULL) = htons(atoi(argv[2]));

			printf("[%s]:%hu => %s\n", sa_ntoa(saddr), ntohs(*sa_port(saddr, SA_PORT_NONE, NULL)), sa_ntoa(sa_egress(&egress, sizeof egress, saddr, 0)));
		} else
			printf("%s => %s\n", sa_ntoa(saddr), sa_ntoa(sa_egress(&egress, sizeof egress, saddr, 0)));
	} else if (!strcmp(*argv, "print") && argv[1]) {
		struct sockaddr *saddr = sa_aton(argv[1]);

		if (AF_UNSPEC == sa_family(saddr))
			goto usage;

		if (argc > 2) {
			*sa_port(saddr, SA_PORT_NONE, NULL) = htons(atoi(argv[2]));

			printf("[%s]:%hu\n", sa_ntoa(saddr), ntohs(*sa_port(saddr, SA_PORT_NONE, NULL)));
		} else {
			*sa_port(saddr, SA_PORT_NONE, NULL) = htons(6970);

			printf("%s\n", sa_ntoa(saddr));
		}
	} else if (!strcmp(*argv, "get") && argv[1]) {
		return httpget(argv[1]);
	} else
		goto usage;

	return 0;
} /* main() */

#endif
