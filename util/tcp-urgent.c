#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#if BSD
#include <sys/event.h>
#endif
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>

#if __clang__
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#elif __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define countof(a) (sizeof (a) / sizeof *(a))

static struct {
	const char *progname;
	_Bool ipv4;
	_Bool ipv6;
	int verbose;
} MAIN = {
	.progname = __FILE__,
	.verbose = 1,
};

#define panic(...) do { \
	say(0, __LINE__, __VA_ARGS__); \
	exit(EXIT_FAILURE); \
} while (0)

#define info(...) do { \
	say(1, __LINE__, __VA_ARGS__); \
} while (0)

#define debug(...) do { \
	say(2, __LINE__, __VA_ARGS__); \
} while (0)

static void say(int level, int lineno, const char *fmt, ...) {
	va_list ap;

	if (level > MAIN.verbose)
		return;

	fprintf(stderr, "%s:", MAIN.progname);
	if (MAIN.verbose > 1)
		fprintf(stderr, "%d:", lineno);
	fputc(' ', stderr);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
} /* say() */

static const char *progname(const char *progname) {
	const char *basename;

	if (!progname || !*progname)
		progname = __FILE__;

	if ((basename = strrchr(progname, '/')) && basename[1])
		return &basename[1];
	
	return progname;
} /* progname() */

static socklen_t getegress(void *dst, socklen_t lim, int family, int type, int protocol, const char *host, const char *port) {
	struct addrinfo hints = { 0, family, type, protocol };
	struct addrinfo *ent0 = NULL, *ent;
	socklen_t len;
	int fd = -1, error;

	if (0 != (error = getaddrinfo(host, port, &hints, &ent0)))
		panic("[%s]:%s: %s", host, port, gai_strerror(error));

	for (ent = ent0; ent != NULL; ent = ent->ai_next) {
		if (-1 == (fd = socket(ent->ai_family, ent->ai_socktype, ent->ai_protocol)))
			panic("socket: %s", strerror(errno));

		if (0 == connect(fd, ent->ai_addr, ent->ai_addrlen))
			break;

		error = errno;
		close(fd);
		fd = -1;
	}

	freeaddrinfo(ent0);

	if (fd == -1)
		panic("connect([%s]:%s): %s", host, port, strerror(error));

	len = lim;
	if (0 != getsockname(fd, dst, &len))
		panic("getsockname: %s", strerror(errno));

	if (len > lim)
		panic("getsockname: output buffer too small");

	close(fd);

	return len;
} /* getegress() */

static in_port_t *sa_port(void *any) {
	if (((struct sockaddr *)any)->sa_family == AF_INET6) {
		return &((struct sockaddr_in6 *)any)->sin6_port;
	} else {
		return &((struct sockaddr_in *)any)->sin_port;
	}
} /* sa_port() */

static void opentcp(int fd[2], int family) {
	struct {
		const char *host, *port;
	} egress;
	union {
		struct sockaddr_storage any;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} saddr;
	socklen_t slen;
	int lfd = -1;

	memset(&saddr, 0, sizeof saddr); /* OS X needs this 0'd out */

	/* find egress address instead of using loopback */
	egress.host = (family == AF_INET6)? "2001:4860:4860::8888" : "8.8.8.8";
	egress.port = "53";
	slen = getegress(&saddr, sizeof saddr, family, SOCK_STREAM, IPPROTO_TCP, egress.host, egress.port);
	*sa_port(&saddr) = 0;

	if (-1 == (lfd = socket(family, SOCK_STREAM, IPPROTO_TCP)))
		panic("socket: %s", strerror(errno));
	if (0 != bind(lfd, (struct sockaddr *)&saddr, slen))
		panic("bind: %s", strerror(errno));
	if (0 != listen(lfd, SOMAXCONN))
		panic("listen: %s", strerror(errno));

	memset(&saddr, 0, sizeof saddr);
	slen = sizeof saddr;
	if (0 != getsockname(lfd, (struct sockaddr *)&saddr, &slen))
		panic("getsockname: %s", strerror(errno));

	if (-1 == (fd[1] = socket(family, SOCK_STREAM, IPPROTO_TCP)))
		panic("socket: %s", strerror(errno));
	if (0 != connect(fd[1], (struct sockaddr *)&saddr, slen))
		panic("connect: %s", strerror(errno));

	if (-1 == (fd[0] = accept(lfd, NULL, NULL)))
		panic("accept: %s", strerror(errno));

	close(lfd);

	return;
} /* opentcp() */

static void closetcp(int fd[2]) {
	close(fd[0]);
	fd[0] = -1;
	close(fd[1]);
	fd[1] = -1;
} /* closetcp() */

static char *strevents(char *dst, size_t lim, short events) {
	static const struct { char text[16]; int flag; } event[] = {
		{ "POLLIN", POLLIN }, { "POLLOUT", POLLOUT },
		{ "POLLRDNORM", POLLRDNORM }, { "POLLWRNORM", POLLWRNORM },
		{ "POLLRDBAND", POLLRDBAND }, { "POLLWRBAND", POLLWRBAND },
		{ "POLLPRI", POLLPRI },
	};
	char *p, *pe;
	size_t i;

	p = dst;
	pe = dst + lim;

	#define p_putc(c) do { if (p < pe) *p++ = (c); } while (0)

	for (i = 0; i < countof(event); i++) {
		const char *tp;

		if (!(event[i].flag & events))
			continue;

		if (p > dst) {
			p_putc(',');
			p_putc(' ');
		}

		for (tp = event[i].text; *tp; tp++)
			p_putc(*tp);
	}

	p_putc('\0');
	assert(lim > 0);
	dst[lim - 1] = '\0';

	#undef p_putc

	return dst;	
} /* strevents() */

#define POLLALL (POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM|POLLRDBAND|POLLWRBAND|POLLPRI)

static short pollpending(int fd, short events) {
	struct pollfd fds[1] = { { .fd = fd, .events = events } };
	int nfd;

	if (-1 == (nfd = poll(fds, 1, 0)))
		panic("poll: %s", strerror(errno));

	return (nfd > 0)? fds[0].revents : 0;
} /* pollpending() */

static short selectpending(int fd, short events) {
	fd_set rd, wr, ex;
	short revents;

	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);

	if (POLLIN & events)
		FD_SET(fd, &rd);
	if (POLLOUT & events)
		FD_SET(fd, &wr);
	if (POLLPRI & events)
		FD_SET(fd, &ex);

	if (-1 == select(fd + 1, &rd, &wr, &ex, &(struct timeval){ 0, 0 }))
		panic("select");

	revents = 0;
	if (FD_ISSET(fd, &rd))
		revents |= POLLIN;
	if (FD_ISSET(fd, &wr))
		revents |= POLLOUT;
	if (FD_ISSET(fd, &ex))
		revents |= POLLPRI;
		
	return revents;
} /* selectpending() */

static short keventpending(int fd, short events) {
#if BSD
	struct kevent event[3], *ep = event;
	short revents;
	int kq, i, n;

#if defined EV_OOBAND
	if (events & (POLLIN|POLLRDNORM|POLLRDBAND|POLLPRI)) {
		int flags = EV_ADD|EV_ONESHOT;
		if (events & (POLLRDBAND|POLLPRI))
			flags |= EV_OOBAND;
		EV_SET(ep, fd, EVFILT_READ, flags, 0, 0, 0);
		ep++;
	}
#else
	if (events & (POLLIN|POLLRDNORM)) {
		EV_SET(ep, fd, EVFILT_READ, EV_ADD|EV_ONESHOT, 0, 0, 0);
		ep++;
	}
#endif

	if (events & POLLOUT) {
		EV_SET(ep, fd, EVFILT_WRITE, EV_ADD|EV_ONESHOT, 0, 0, 0);
		ep++;
	}

	if (-1 == (kq = kqueue()))
		panic("kqueue");

	if (-1 == (n = kevent(kq, event, ep - event, event, countof(event), &(struct timespec){ 0, 0 })))
		panic("kevent");

	close(kq);

	revents = 0;

	for (i = 0; i < n; i++) {
		if (event[i].filter == EVFILT_READ) {
#if defined EV_OOBAND
			if (event[i].flags & EV_OOBAND)
				revents |= events & (POLLPRI|POLLRDBAND);

			/* NB: no way to know whether _only_ OOB available */
#endif
			revents |= events & (POLLIN|POLLRDNORM);
		} else if (event[i].filter == EVFILT_WRITE) {
			revents |= POLLOUT;
		}
	}

	return revents;
#else
	return 0;
#endif
} /* keventpending() */

static void showpending(int fd, short events) {
	char text[128];
	short revents;

	info("checking events: %s", strevents(text, sizeof text, events));

	revents = pollpending(fd, events);
	info("  poll:   %s", strevents(text, sizeof text, revents));

	revents = selectpending(fd, events);
	info("  select: read:%d write:%d except:%d", !!(revents & POLLIN), !!(revents & POLLOUT), !!(revents & POLLPRI));

	revents = keventpending(fd, events);
	info("  kevent: %s", strevents(text, sizeof text, revents));
} /* showpending() */

static void checktcp(int fd[2]) {
	char data[32], urgent[1];
	ssize_t n;

	memset(data, 'A', sizeof data);
	memset(urgent, '!', sizeof urgent);

	if (-1 == (n = send(fd[1], urgent, sizeof urgent, MSG_OOB)))
		panic("send");

	info("sent %d bytes of OOB data", n);
	showpending(fd[0], POLLALL);

	if (-1 == (n = send(fd[1], data, sizeof data, 0)))
		panic("send");

	info("sent %d bytes of normal data", n);
	showpending(fd[0], POLLALL);

	return;
} /* checktcp() */

#define SHORTOPTS "64qvh"

static void usage(FILE *fp) {
	fprintf(fp, \
		"Usage: %s [-" SHORTOPTS "]\n" \
		"  -4  use IPv4\n" \
		"  -6  use IPv6\n" \
		"  -q  do not show information messages\n" \
		"  -v  enable verbose logging\n" \
		"  -h  print this usage message\n" \
		"\n" \
		"Report bugs to <william@25thandClement.com>\n",
		MAIN.progname);
} /* usage() */

int main(int argc, char **argv) {
	int fd[2] = { -1, -1 };
	int optc;

	MAIN.progname = progname((argc > 0)? argv[0] : NULL); 

	while (-1 != (optc = getopt(argc, argv, SHORTOPTS))) {
		switch (optc) {
		case '4':
			MAIN.ipv4 = 1;
			break;
		case '6':
			MAIN.ipv6 = 1;
			break;
		case 'q':
			MAIN.verbose = 0;
			break;
		case 'v':
			MAIN.verbose++;
			break;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return EXIT_FAILURE;
		}
	}

	if (!(MAIN.ipv4 || MAIN.ipv6))
		MAIN.ipv4 = MAIN.ipv6 = 1;

	if (MAIN.ipv4) {
		opentcp(fd, AF_INET);
		checktcp(fd);
		closetcp(fd);
	}

	if (MAIN.ipv6) {
		opentcp(fd, AF_INET6);
		checktcp(fd);
		closetcp(fd);
	}

	return 0;
} /* main() */
