/* ==========================================================================
 * socket.h - Simple Sockets
 * --------------------------------------------------------------------------
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014  William Ahern
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
#ifndef SOCKET_H
#define SOCKET_H

#include <time.h>        /* time_t */
#include <string.h>      /* memcpy(3) */
#include <errno.h>       /* EAFNOSUPPORT */

#include <sys/types.h>   /* socklen_t in_port_t uid_t gid_t pid_t */
#include <sys/uio.h>     /* struct iovec */
#include <sys/socket.h>	 /* AF_INET AF_INET6 AF_UNIX SOCK_STREAM SHUT_RD SHUT_WR SHUT_RDWR struct sockaddr struct msghdr struct cmsghdr */
#if defined(AF_UNIX)
#include <sys/un.h>
#endif
#include <poll.h>        /* POLLIN POLLOUT */
#include <netinet/in.h>  /* struct sockaddr_in struct sockaddr_in6 */

#include <openssl/ssl.h> /* SSL_CTX SSL */
#include <openssl/err.h> /* ERR_get_error() */


/*
 * V E R S I O N  I N T E R F A C E S
 *
 * Vendor: Entity for which versions numbers are relevant. (If forking
 * change SOCKET_VENDOR to avoid confusion.)
 *
 * Three versions:
 *
 * REL	Official "release"--bug fixes, new features, etc.
 * ABI	Changes to existing object sizes or parameter types.
 * API	Changes that might effect application source.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define SOCKET_VENDOR "william@25thandClement.com"

#define SOCKET_V_REL  0x20170505
#define SOCKET_V_ABI  0x20161213
#define SOCKET_V_API  0x20161213

const char *socket_vendor(void);

int socket_v_rel(void);
int socket_v_abi(void);
int socket_v_api(void);


/*
 * T Y P E  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if _WIN32
typedef short sa_family_t;
typedef unsigned short in_port_t;
#endif


/*
 * D E B U G  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern int socket_debug;


/*
 * E R R O R  I N T E R F A C E S
 *
 * System errors--always positive--are returned as-is. Internal errors are
 * returned as negative integers with a mask in the top 23 bits equivalent
 * to "sck".
 *
 * OpenSSL errors must be handled out-of-band because they're not simple
 * integer codes. When SO_EOPENSSL is encountered, the application must
 * query OpenSSL's per-thread error queue if it wants more information.
 * so_strerror(SO_EOPENSSL) will attempt to return something reasonable by
 * peeking into the OpenSSL error queue.
 *
 * TLS/SSL operations will clear the OpenSSL error queue before proceeding.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define SO_EBASE (-(('s' << 24) | ('c' << 16) | ('k' << 8) | '9'))

enum so_errno {
	SO_EOPENSSL = SO_EBASE,
	SO_EX509INT,	/* See SSL_ERROR_WANT_X509_LOOKUP in SSL_get_error(3). */
	SO_ENOTVRFD,
	SO_ECLOSURE,
	SO_ENOHOST,
	SO_ELAST,
}; /* enum so_errno */

const char *so_strerror(int);

#define SO_ERRNO0 SO_EBASE
#define SO_EEND SO_ELAST
#define SO_ISERRNO(e) ((e) >= SO_ERRNO0 && (e) < SO_EEND)

#define so_error_t int /* for documentation only */


/*
 * O P T I O N  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

typedef struct {
	enum {
		SO_OPT_UNSET = 0,
		SO_OPT_BOOLEAN,
	} type;

	union {
		_Bool boolean;
	};
} so_optional;

struct so_options {
	const void *sa_bind;

	mode_t sun_mode;
	mode_t sun_mask;
	_Bool sun_unlink;

	_Bool sin_reuseaddr;
	_Bool sin_reuseport;
	_Bool sin_broadcast;
	_Bool sin_nodelay;
	_Bool sin_nopush;
	_Bool sin_oobinline;

	enum {
		SO_V6ONLY_DEFAULT = 0, /* system default */
		SO_V6ONLY_ENABLE  = 1,
		SO_V6ONLY_DISABLE = 2,
	} sin_v6only;

	_Bool fd_nonblock;
	_Bool fd_cloexec;
	_Bool fd_nosigpipe;

	enum {
		SO_SYSPOLL,
		SO_LIBEVENT,
	} fd_events;

	struct {
		void *arg;
		int (*cb)(int *fd, void *arg);
	} fd_close;

	_Bool tls_verify;
	const char *tls_sendname;

	_Bool st_time;
}; /* struct so_options */

#define SO_OPTS_TLS_HOSTNAME ((char *)1) /* place holder for peer host name */

#define so_opts(...)	(&(struct so_options){ .sin_reuseaddr = 1, .sin_v6only = SO_V6ONLY_DEFAULT, .fd_nonblock = 1, .fd_cloexec = 1, .fd_nosigpipe = 1, .tls_sendname = SO_OPTS_TLS_HOSTNAME, .st_time = 1, __VA_ARGS__ })

static inline _Bool so_isbool(const so_optional v) {
	return v.type == SO_OPT_BOOLEAN;
}

static inline _Bool so_optbool(const so_optional v, _Bool def) {
	return (so_isbool(v))? v.boolean : def;
}

static inline _Bool so_tobool(const so_optional v) {
	return so_optbool(v, 0);
}

static inline void so_setbool(so_optional *v, _Bool b) {
	v->type = SO_OPT_BOOLEAN;
	v->boolean = b;
}


/*
 * P R E - P R O C E S S O R  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define SO_MIN(a, b) (((a) < (b))? (a) : (b))
#define SO_MAX(a, b) (((a) > (b))? (a) : (b))

#define SO_NARG_(_15, _14, _13, _12, _11, _10, _9, _8, _7, _6, _5, _4, _3, _2, _1, N, ...) N
#define SO_NARG(...) SO_NARG_(__VA_ARGS__, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define SO_PASTE(a, b) a ## b
#define SO_XPASTE(a, b) SO_PASTE(a, b)


/*
 * A D D R E S S  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define SA_UNIX defined(AF_UNIX) && !_WIN32

union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_storage ss;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
#if SA_UNIX
	struct sockaddr_un sun;
#endif
}; /* union sockaddr_any */

/*
 * GCC 4.4's strong aliasing constraints complain about casting through
 * intermediate void pointers before taking a reference to an object member.
 * Use sockaddr_arg_t where we might use the void pointer, and use the
 * accessor function sockaddr_ref() to return the union sockaddr_arg object.
 */
#if __GNUC__
#define SO_TRANSPARENT __attribute__((__transparent_union__))
#define SO_EXTENSION __extension__
#else
#define SO_TRANSPARENT
#define SO_EXTENSION
#endif

union sockaddr_arg {
	struct sockaddr *sa;
	const struct sockaddr *c_sa;

	struct sockaddr_storage *ss;
	struct sockaddr_storage *c_ss;

	struct sockaddr_in *sin;
	struct sockaddr_in *c_sin;

	struct sockaddr_in6 *sin6;
	struct sockaddr_in6 *c_sin6;

#if SA_UNIX
	struct sockaddr_un *sun;
	struct sockaddr_un *c_sun;
#endif
	union sockaddr_any *any;
	union sockaddr_any *c_any;

	void *ptr;
	void *c_ptr;
} SO_TRANSPARENT;

#if __GNUC__
typedef union sockaddr_arg sockaddr_arg_t;

static inline union sockaddr_arg sockaddr_ref(sockaddr_arg_t arg) {
	return arg;
} /* sockaddr_ref() */
#else
typedef void *sockaddr_arg_t;

static inline union sockaddr_arg sockaddr_ref(sockaddr_arg_t arg) {
	return (union sockaddr_arg){ arg };
} /* sockaddr_ref() */
#endif

static inline socklen_t af_len(sa_family_t af) {
	switch (af) {
	case AF_INET:
		return sizeof (struct sockaddr_in);
	case AF_INET6:
		return sizeof (struct sockaddr_in6);
#if SA_UNIX
	case AF_UNIX:
		return sizeof (struct sockaddr_un);
#endif
	default:
		return 0;
	}
} /* af_len() */


#define sa_family(...) SO_EXTENSION sa_family(__VA_ARGS__)

static inline sa_family_t *(sa_family)(sockaddr_arg_t arg) {
	return &sockaddr_ref(arg).sa->sa_family;
} /* sa_family() */


#define sa_len(...) SO_EXTENSION sa_len(__VA_ARGS__)

static inline socklen_t (sa_len)(sockaddr_arg_t arg) {
	return af_len(*sa_family(arg));
} /* sa_len() */


#if SA_UNIX
#define SA_ADDR_NONE (&(union { struct in_addr addr; struct in6_addr addr6; char path[sizeof ((struct sockaddr_un *)0)->sun_path]; }))
#else
#define SA_ADDR_NONE (&(union { struct in_addr addr; struct in6_addr addr6; }))
#endif

#define sa_addr(...) SO_EXTENSION sa_addr(__VA_ARGS__)

static inline void *(sa_addr)(sockaddr_arg_t arg, const void *def, int *error) {
	switch (*sa_family(arg)) {
	case AF_INET:
		return &sockaddr_ref(arg).sin->sin_addr;
	case AF_INET6:
		return &sockaddr_ref(arg).sin6->sin6_addr;
#if SA_UNIX
	case AF_UNIX:
		return &sockaddr_ref(arg).sun->sun_path;
#endif
	default:
		if (error)
			*error = EAFNOSUPPORT;

		return (void *)def;
	}
} /* sa_addr() */


#define sa_addrlen(...) SO_EXTENSION sa_addrlen(__VA_ARGS__)

static inline socklen_t (sa_addrlen)(sockaddr_arg_t arg, int *error) {
	switch (*sa_family(arg)) {
	case AF_INET:
		return sizeof ((struct sockaddr_in *)0)->sin_addr;
	case AF_INET6:
		return sizeof ((struct sockaddr_in6 *)0)->sin6_addr;
#if SA_UNIX
	case AF_UNIX:
		return sizeof ((struct sockaddr_un *)0)->sun_path;
#endif
	default:
		if (error)
			*error = EAFNOSUPPORT;

		return 0;
	}
} /* sa_addrlen() */


#define SA_PORT_NONE (&(in_port_t){ 0 })

#define sa_port(...) SO_EXTENSION sa_port(__VA_ARGS__)

static inline in_port_t *(sa_port)(sockaddr_arg_t arg, const in_port_t *def, int *error) {
	switch (*sa_family(arg)) {
	case AF_INET:
		return &sockaddr_ref(arg).sin->sin_port;
	case AF_INET6:
		return &sockaddr_ref(arg).sin6->sin6_port;
	default:
		if (error)
			*error = EAFNOSUPPORT;

		return (in_port_t *)def;
	}
} /* sa_port() */


#if SA_UNIX
#define SA_ADDRSTRLEN SO_MAX(INET6_ADDRSTRLEN, (sizeof ((struct sockaddr_un *)0)->sun_path) + 1)
#else
#define SA_ADDRSTRLEN INET6_ADDRSTRLEN
#endif

char *sa_ntop(char *, size_t, const void *, const char *, so_error_t *);

void *sa_pton(void *, size_t, const char *, const void *, so_error_t *);

static inline char *sa_ntoa_(char *dst, size_t lim, const void *src) {
	return sa_ntop(dst, lim, src, NULL, &(int){ 0 }), dst;
} /* sa_ntoa_() */

static inline void *sa_aton_(void *dst, size_t lim, const char *src) {
	return sa_pton(dst, lim, src, NULL, &(int){ 0 }), dst;
} /* sa_aton_() */

#define sa_ntoa(sa)  sa_ntoa_((char [SA_ADDRSTRLEN]){ 0 }, SA_ADDRSTRLEN, (sa))

#define sa_aton(str) sa_aton_(&(struct sockaddr_storage){ 0 }, sizeof (struct sockaddr_storage), (str))


/*
 * U T I L I T Y  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define so_itoa_putc(c) do { if (p < lim) dst[p] = (c); p++; } while (0)

static inline char *so_itoa(char *dst, size_t lim, long i) {
	size_t p = 0;
	long d = 1000000000L, n = 0, r;

	if (i < 0) {
		so_itoa_putc('-');
		i *= -1;
	}

	if ((i = SO_MIN(2147483647L, i))) {
		do {
			if ((r = i / d) || n) {
				i -= r * d;
				n++;
				so_itoa_putc('0' + r);
			}
		} while (d /= 10);
	} else
		so_itoa_putc('0');

	if (lim)
		dst[SO_MIN(p, lim - 1)] = '\0';

	return dst;
} /* so_itoa() */

#define so_itoa3(d, l, i) so_itoa((d), (l), (i))
#define so_itoa1(i)       so_itoa3((char[32]){ 0 }, 32, (i))
#define so_itoa(...)      SO_XPASTE(so_itoa, SO_NARG(__VA_ARGS__))(__VA_ARGS__)

#define so_isint(T) \
	(__builtin_types_compatible_p(char, T) || \
	 __builtin_types_compatible_p(signed char, T) || \
	 __builtin_types_compatible_p(unsigned char, T) || \
	 __builtin_types_compatible_p(signed short, T) || \
	 __builtin_types_compatible_p(unsigned short, T) || \
	 __builtin_types_compatible_p(signed int, T) || \
	 __builtin_types_compatible_p(unsigned int, T) || \
	 __builtin_types_compatible_p(signed long, T) || \
	 __builtin_types_compatible_p(unsigned long, T) || \
	 __builtin_types_compatible_p(signed long long, T) || \
	 __builtin_types_compatible_p(unsigned long long, T))

#define so_ytoa(y) \
	__builtin_choose_expr(so_isint(__typeof__(y)), so_itoa((long)(y)), (y))


void *sa_egress(void *, size_t, sockaddr_arg_t, int *);

int so_socket(int, int, const struct so_options *, int *);

int so_bind(int, sockaddr_arg_t, const struct so_options *);

void so_closesocket(int *, const struct so_options *);

int so_nonblock(int, _Bool);

int so_cloexec(int, _Bool);

int so_reuseaddr(int, _Bool);

int so_reuseport(int, _Bool);

int so_broadcast(int, _Bool);

int so_nodelay(int, _Bool);

int so_nopush(int, _Bool);

int so_nosigpipe(int, _Bool);

int so_v6only(int, _Bool);

int so_oobinline(int, _Bool);

#define SO_F_CLOEXEC   0x0001
#define SO_F_NONBLOCK  0x0002
#define SO_F_REUSEADDR 0x0004
#define SO_F_REUSEPORT 0x0008
#define SO_F_BROADCAST 0x0010
#define SO_F_NODELAY   0x0020
#define SO_F_NOPUSH    0x0040
#define SO_F_NOSIGPIPE 0x0080
#define SO_F_V6ONLY    0x0100
#define SO_F_OOBINLINE 0x0200

int so_getfl(int fd, int which); /* no failure mode */

so_error_t so_rstfl(int fd, int *oflags, int flags, int mask, int require);

so_error_t so_setfl(int fd, int flags, int mask, int require);

so_error_t so_addfl(int fd, int flags, int require);

#define so_addfl3(fd, flags, require, ...) so_addfl((fd), (flags), (require))
#define so_addfl(...) so_addfl3(__VA_ARGS__, ~0)

so_error_t so_delfl(int fd, int flags, int require);

#define so_delfl3(fd, flags, require, ...) so_delfl((fd), (flags), (require))
#define so_delfl(...) so_delfl3(__VA_ARGS__, ~0)


/*
 * S O C K E T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct socket;

struct socket *so_open(const char *, const char *, int, int, int, const struct so_options *, int *);

#if __GNUC__ /* Coerce port to string if not already. */
#define so_open(host, port, ...) so_open((host), so_ytoa((port)), __VA_ARGS__)
#else
#define so_open(...) so_open(__VA_ARGS__)
#endif

struct socket *so_dial(const struct sockaddr *, int, const struct so_options *, int *);

struct socket *so_fdopen(int, const struct so_options *, int *);

int so_close(struct socket *);

int so_family(struct socket *, int *);

int so_localaddr(struct socket *, void *, socklen_t *);

int so_remoteaddr(struct socket *, void *, socklen_t *);

int so_connect(struct socket *);

int so_listen(struct socket *);

int so_accept(struct socket *, struct sockaddr *, socklen_t *, int *);

struct so_starttls {
	SSL_METHOD *method;
	SSL_CTX *context;
	SSL *instance;

	struct iovec pushback;

	so_optional accept;
}; /* struct so_starttls */

int so_starttls(struct socket *, const struct so_starttls *);

SSL *so_checktls(struct socket *);

int so_shutdown(struct socket *, int /* SHUT_RD, SHUT_WR, SHUT_RDWR */);

size_t so_read(struct socket *, void *, size_t, int *);

size_t so_write(struct socket *, const void *, size_t, int *);

#define SO_F_PEEKALL 0x01

size_t so_peek(struct socket *, void *, size_t, int, int *);

#define so_peekall(so, dst, lim, ep) so_peek((so), (dst), (lim), SO_F_PEEKALL, (ep))
#define so_peekany(so, dst, lim, ep) so_peek((so), (dst), (lim), 0, (ep))


/*
 * NOTE: CMSG_SPACE does not evaluate to a constant on OS X or NetBSD, so
 * cannot be used to declare a compound literal. Instead, a largish constant
 * is used. It must be adjusted at run-time because some implementations
 * complain if .msg_controllen is too large.
 */
#define so_fdmsgbuf() (&(struct msghdr){ \
	.msg_iov = &(struct iovec){ 0, 0 }, \
	.msg_iovlen = 1, \
	.msg_control = &(union { char buf[64]; struct cmsghdr hdr; }){ { 0 } }, \
	.msg_controllen = 64 \
})

static inline struct msghdr *so_fdmsg_(struct msghdr *msg, const void *p, size_t n, int fd) {
	msg->msg_iov->iov_base = (void *)p;
	msg->msg_iov->iov_len = n;
	msg->msg_controllen = SO_MIN(msg->msg_controllen, CMSG_SPACE(sizeof (int)));
	struct cmsghdr *cmsg;
	cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof (int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof fd);
	return msg;
} /* so_fdmsg_() */

#define so_fdmsg(p, n, fd) so_fdmsg_(so_fdmsgbuf(), (p), (n), (fd))

int so_sendmsg(struct socket *, const struct msghdr *, int);

int so_recvmsg(struct socket *, struct msghdr *, int);


struct so_stat {
	struct st_log {
		unsigned long long count;
		_Bool eof;
		time_t time;
	} sent, rcvd;
}; /* struct so_stat */

const struct so_stat *so_stat(struct socket *);

#define SO_POLL2EV(set) \
	(((set) & POLLIN)? 2 : 0) | (((set) & POLLOUT)? 4 : 0)

int so_events(struct socket *);

void so_clear(struct socket *);

int so_pollfd(struct socket *);

int so_poll(struct socket *, int);

int so_peerfd(struct socket *);

int so_uncork(struct socket *);

int so_peereid(struct socket *, uid_t *, gid_t *);
int so_peerpid(struct socket *, pid_t *);


/*
 * L I B R A R Y  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void socket_init(void);


#endif /* SOCKET_H */
