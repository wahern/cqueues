The following is a list of porting issues discovered while implementing
cqueues, maintained in the spirit of
[DJB's portability notes](http://cr.yp.to/docs/unixport.html).

---------------------------------------------------------------------------

### `FD_SETSIZE`

  - `int` : Linux 3.2.0 (glibc 2.15)
  - `int` : OS X 10.7
  - `int` : OpenBSD 5.1
  - `int` : Solaris 11.0
  - `unsigned int` : FreeBSD 9.0
  - `int` : NetBSD 5.1.2

Last updated 2012-08-16.

---------------------------------------------------------------------------

### `.msg_iovlen` of `struct msghdr`

  - `size_t` : Linux 3.2.0 (glibc 2.15)
  - `int` : OS X 10.7
  - `unsigned int` : OpenBSD 5.1
  - `int` : Solaris 11.0
  - `int` : FreeBSD 9.0
  - `int` : NetBSD 5.1.2
  - `size_t` : RFC 2292
  - `int` : SUSv4

Last updated 2012-08-16.

---------------------------------------------------------------------------

### `CMSG_SPACE`

Not always a constant expression, so cannot be used to declare a
compound literal.

  - constant : Linux 3.2.0 (glibc 2.15)
  - not constant : OS X 10.7
  - constant : OpenBSD 5.1
  - constant : Solaris 11.0
  - constant : FreeBSD 9.0
  - not constant : NetBSD 5.1.2

Last updated 2012-08-16.

---------------------------------------------------------------------------

### `sendmsg`, `SCM_RIGHTS`

OS X will completely shutdown a socket and free pending data for an
inflight descriptor lacking a process reference. Nonethelss, recvmsg
will return a valid socket descriptor as ancillary `SCM_RIGHTS` data.

Confirmed OS X 10.7, OS X 10.8.
Last updated 2012-08-14.

See also [`SO_NOSIGPIPE`](#so_nosigpipe-f_setnosigpipe).

---------------------------------------------------------------------------

### `SO_NOSIGPIPE`, `F_SETNOSIGPIPE`

OS X will fail with `EINVAL` an attempt to set the `SO_NOSIGPIPE` option
on some streams which have been terminated. Examples:

  - On a socketpair descriptor where the peer has called
    `shutdown(SHUT_RDWR)`.
  - On a TCP stream after both peers exchanged FIN, e.g. by each
    calling `shutdown(SHUT_WR)`.
  - On a TCP stream after a send call has returned `EPIPE`, e.g. by the
    peer calling close, triggering RST.

Receiving RST from a peer was not sufficient alone to fail
setsockopt. Nor was a mere call to `shutdown(SHUT_WR)` by the host.

Confirmed OS X 10.7.

Last updated 2012-08-16.

See also [shutdown](#shutdown).

---------------------------------------------------------------------------

### shutdown

OS X will fail with `ENOTCONN` a shutdown attempt if the specified
`SHUT_RD` or `SHUT_WR` flag was already set, or if the respective TCP
state was already reached. In particular, if FIN was received from
the sender then shutdown(SHUT_RD) will fail.

Confirmed OS X 10.7.

Last updated 2012-08-16.

---------------------------------------------------------------------------

### `fchmod` on `AF_UNIX` socket

  - OK : Linux 3.2.0 (glibc 2.15)
  - `EINVAL` : OS X 10.8.1
  - `EINVAL` : OpenBSD 5.1
  - OK : Solaris 11.0
  - `EINVAL` : FreeBSD 9.0
  - `EINVAL` : NetBSD 5.1.2

#### NOTES:

  - Solaris does not actually obey `AF_UNIX` socket file permissions.
  - `fchmod` on Linux is useful because it addresses the race
    condition of `bind`+`chmod`--if you `fchmod` the socket before
    binding, the directory entry permissions are inherited
    without having to bother with thread-unfriendly umask
    fiddling. More portable alternatives are to bind the
    socket into a private directory first, or to rely on peer
    credentials at accept.

Last updated 2012-09-15.

---------------------------------------------------------------------------

### `AF_UNIX` socket file permissions

  -   obeys : Linux 3.2.0 (glibc 2.15)
  -   obeys : OS X 10.8.1
  -   obeys : OpenBSD 5.1
  - ignores : Solaris 11.0
  -   obeys : FreeBSD 9.0
  -   obeys : NetBSD 5.1.2

Last updated 2012-09-15.

---------------------------------------------------------------------------

### `pselect`

  -  OK : Linux 3.2.0 (glibc 2.15)
  -  broken : OS X 10.8.1
  -  NO : OpenBSD 5.1
  -  OK : Solaris 11.0
  -  OK : FreeBSD 9.0
  -  broken : NetBSD 5.1.2

OS X appears to merely set and reset the signal mask around a call
to `select`, which doesn't address the signal race at all.

OpenBSD 5.1 does not provide `pselect`.

NetBSD 5.1 fails to deliver signals inside `pselect`, including
pending signals, although it does interrupt when a signal arrives.

A kqueue-portable implementation is feasible using `EVFILT_SIGNAL`:

 1. install `EVFILT_SIGNAL` for the signal set currently blocked but
    soon to be unblocked
 2. check sigpending for such signal set
 3. install requested signal mask
 4. call select with kqueue descriptor added to the read fd_set
 5. restore signal mask
 6. check return values from select and kqueue

Non-obviousness:

  - Any other signal set than described above could be lost even with
    a kernel pselect. An implementation could elect to minimize the
    race condition, but that would merely postpone the inevitable.
  - `EVFILT_SIGNAL` is edge triggered, so it won't catch pending signals
    delivered upon unblocking, thus the necessity to call sigpending
    after `kevent`, but before `sigprocmask`/`pthread_sigmask`.
  - The above scheme is susceptiple to spurious wakeup, e.g. by
    `SIG_IGN` handlers which wouldn't interrupt a kernel `pselect`.

Last updated 2012-09-21.

---------------------------------------------------------------------------

### `(struct kevent).udata`

  -   `void *` : OS X 10.8.2
  -   `void *` : OpenBSD 5.1
  -   `void *` : FreeBSD 9.0
  - `intptr_t` : NetBSD 5.1.2

NetBSD circa 2002 changed the .udata type to intptr_t.
Workaround: cast to `(__typeof__(((struct kevent *)0)->udata))`.

Last updated 2012-09-21.

---------------------------------------------------------------------------

### Linux `connect(2)` associations

Linux will not reassociate a UDP socket to a non-loopback address if
the first association was to the loopback. No other system exhibits
this behavior.

An argument can be made that reassociations should fail if the
existing source address (perhaps auto-bound on the first
association) does not match the new destination network. But this
has apparently always been allowed on various systems as far as I
can tell, even on previous versions of Linux.

A work around is to break an existing association by connecting to
`AF_UNSPEC`.

This bug/feature can manifest, for example, when your
/etc/resolv.conf files looks like

	nameserver 127.0.0.1
	nameserver 1.2.3.4

and the DNS resolver uses `connect(2)` to efficiently filter replies.
Failover of queries from 127.0.0.1 to 1.2.3.4 will return a system
error because Linux will return `EINVAL` when reassociating the socket
with connect(udp-socket, 1.2.3.4).

Reassociating from loopback to external address:

  - `EINVAL`: Linux 3.2.0 (and various 3.x)
  -  OK : OS X 10.8.2
  -  OK : OpenBSD 5.1
  -  OK : OpenBSD 5.2
  -  OK : Solaris 11.0
  -  OK : FreeBSD 9.0
  -  OK : NetBSD 5.1.2

Last updated 2013-03-02.

---------------------------------------------------------------------------

### `SO_ACCEPTCONN`

`SO_ACCEPTCONN` is unsupported on many BSDs due to an old bug which
(supposedly) has been intentionally carried forward.

  - OK : Linux 3.2.0
  - `ENOPROTOOPT` : OS X 10.9.3
  - `ENOPROTOOPT` : OpenBSD 5.5
  - OK : Solaris 11.1
  - OK : FreeBSD 9.0
  - `ENOPROTOOPT` : NetBSD 6.1.1

Last updated 2014-07-01.

---------------------------------------------------------------------------

### `getsockname` and `getpeername` on `AF_UNIX` socket

The socket address returned for both named and unnamed AF_UNIX sockets
differs among systems. Applications must be sure to check the returned
socket address length as it won't always match the length of the associated
socket address structure, and in some cases might be 0.

NOTE:
  - An rlen of 0 did not mean that the syscall failed. No syscalls failed in
    the generation of this dataset.
  - For socketpair the first descriptor was used to query the behavior.

```
system       | fd         | syscall     | rlen | .sa_family | .sun_path
=================================================================================
AIX 7.1      | listen     | getsockname | 1025 | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 1025 | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 16   | AF_UNIX    | empty
             | connect    | getsockname | 0    | unset      | -
             | connect    | getpeername | 1025 | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 0    | unset      | -
             | socketpair | getpeername | 16   | AF_UNIX    | empty
---------------------------------------------------------------------------------
Solaris 11.2 | listen     | getsockname | 110  | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 110  | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 16   | AF_UNIX    | empty
             | connect    | getsockname | 0    | unset      | -
             | connect    | getpeername | 110  | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 16   | AF_UNIX    | empty
             | socketpair | getpeername | 0    | unset      | -
---------------------------------------------------------------------------------
Linux 3.16   | listen     | getsockname | 13   | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 13   | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 2    | AF_UNIX    | unset
             | connect    | getsockname | 2    | AF_UNIX    | unset
             | connect    | getpeername | 13   | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 2    | AF_UNIX    | unset
             | socketpair | getpeername | 2    | AF_UNIX    | unset
---------------------------------------------------------------------------------
FreeBSD 10.1 | listen     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 16   | AF_UNIX    | empty
             | connect    | getsockname | 16   | AF_UNIX    | empty
             | connect    | getpeername | 106  | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 16   | AF_UNIX    | empty
             | socketpair | getpeername | 16   | AF_UNIX    | empty
---------------------------------------------------------------------------------
NetBSD 6.1.5 | listen     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 106  | AF_UNIX    | empty
             | connect    | getsockname | 106  | AF_UNIX    | empty
             | connect    | getpeername | 106  | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 106  | AF_UNIX    | empty
             | socketpair | getpeername | 106  | AF_UNIX    | empty
---------------------------------------------------------------------------------
OpenBSD 5.6  | listen     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 16   | AF_UNIX    | empty
             | connect    | getsockname | 16   | AF_UNIX    | empty
             | connect    | getpeername | 106  | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 16   | AF_UNIX    | empty
             | socketpair | getpeername | 16   | AF_UNIX    | empty
---------------------------------------------------------------------------------
Minix 3.3    | listen     | getsockname | 106  | AF_UNIX    | set    (/tmp/getname.012688aa/named.sock)
             | accept     | getsockname | 106  | AF_UNIX    | set    (/tmp/getname.012688aa/named.sock)
             | accept     | getpeername | 106  | AF_UNIX    | set    (/tmp/getname.012688aa/named.sock)
             | connect    | getsockname | 106  | AF_UNIX    | set    (/tmp/getname.012688aa/named.sock)
             | connect    | getpeername | 106  | AF_UNIX    | set    (/tmp/getname.012688aa/named.sock)
             | socketpair | getsockname | 106  | AF_UNIX    | set    (X)
             | socketpair | getpeername | 106  | AF_UNIX    | set    (X)
---------------------------------------------------------------------------------
OS X 10.10.5 | listen     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getsockname | 106  | AF_UNIX    | set    (named.sock)
             | accept     | getpeername | 16   | AF_UNIX    | empty
             | connect    | getsockname | 16   | AF_UNIX    | empty
             | connect    | getpeername | 106  | AF_UNIX    | set    (named.sock)
             | socketpair | getsockname | 16   | AF_UNIX    | empty
             | socketpair | getpeername | 16   | AF_UNIX    | empty
```

Last updated 2015-08-10.

---------------------------------------------------------------------------

### APPENDIX

	// fchmod and AF_UNIX socket permission checking
	// Last updated 2012-09-15
	#include <stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#include <errno.h>

	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/socket.h>
	#include <sys/un.h>
	#include <unistd.h>

	#undef sun

	#if __clang__
	_Pragma("clang diagnostic ignored \"-Wunused\"")
	#elif __GNUC__
	_Pragma("GCC diagnostic ignored \"-Wunused\"")
	#endif

	#define expect(rv, cmp, fn, ...) ({ \
		__typeof__(rv) tmp = fn(__VA_ARGS__); \
		if (rv cmp tmp) { \
			puts(#fn ": OK"); \
		} else { \
			printf(#fn ": %s\n", strerror(errno)); \
			_Exit(EXIT_FAILURE); \
		} \
		tmp; \
	})

	int main(int argc, char **argv) {
		extern char *optarg;
		extern int optind;
		const char *path = "mode.sock";
		int mode = 0, mask = 0777;
		const char *op;
		int opt, srv = -1, cli = -1;

		while (-1 != (opt = getopt(argc, argv, "p:m:u:"))) {
			switch (opt) {
			case 'p':
				path = optarg;
				break;
			case 'm':
				mode = strtol(optarg, NULL, 8);
				break;
			case 'u':
				mask = strtol(optarg, NULL, 8);
				break;
			default:
				break;
			}
		}

		argc -= optind;
		argv += optind;

		srv = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
		unlink(path);

		struct sockaddr_un sun;
		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, path, sizeof sun.sun_path);

		op = (argc > 0)? *argv : "blc";

		while (*op) {
			switch (*op++) {
			case 'b':
				expect(0, ==, bind, srv, (void *)&sun, sizeof sun);
				break;
			case 'l':
				expect(0, ==, listen, srv, SOMAXCONN);
				break;
			case 'c':
				expect(0, ==, chmod, path, mode);
				break;
			case 'f':
				expect(0, ==, fchmod, srv, mode);
				break;
			case 'u':
				umask(mask);
				puts("umask: OK");
				break;
			default:
				fprintf(stderr, "%c: unknown operation\n", op[-1]);
			}
		}

		cli = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
		expect(0, ==, connect, cli, (void *)&sun, sizeof sun);

		return 0;
	} /* main() */

---------------------------------------------------------------------------

	// pselect
	#define USE_PTHREAD 0
	#include <signal.h>
	#include <sys/select.h>
	#include <unistd.h>

	static void noop() {
		write(STDERR_FILENO, "rcvd\n", 5);
	}

	int main(void) {
		struct sigaction act;
		sigset_t omask, mask;

		act.sa_handler = &noop;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGINT, &act, NULL);

		raise(SIGINT);

		sigemptyset(&mask);
		sigemptyset(&omask);
		sigaddset(&mask, SIGINT);
	#if USE_PTHREAD
		pthread_sigmask(SIG_BLOCK, &mask, &omask);
	#else
		sigprocmask(SIG_BLOCK, &mask, &omask);
	#endif

		raise(SIGINT);

		sigdelset(&omask, SIGINT);
		pselect(0, NULL, NULL, NULL, NULL, &omask);

		return 0;
	}

---------------------------------------------------------------------------

	// getsockname and getpeername on AF_UNIX socket
	#include <stddef.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <errno.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <sys/un.h>
	#include <sys/stat.h>
	#include <unistd.h>
	#include <fcntl.h>

	#undef sun

	#define SAY_(file, func, line, fmt, ...) \
	        fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)
	#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")
	#define HAI SAY("hai")

	#define panic(...) do { SAY(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)
	#define panic_m_(fmt, ...) panic(fmt ": %s", __VA_ARGS__)
	#define panic_m(...) panic_m_(__VA_ARGS__, strerror(errno))

	static struct {
		char root[128], name[128];
	} tmp = {
		.root = "/tmp/getname.XXXXXXXX",
		.name = "named.sock",
	};

	static void rmtmpdir(void) {
		unlink(tmp.name);

		if (0 != chdir(".."))
			panic_m("chdir ..");

		if (0 != rmdir(tmp.root))
			panic_m("rmdir %s", tmp.root);
	} /* rmtmpdir() */

	static void mktmpdir(void) {
		if (!mktemp(tmp.root))
			panic_m("mktemp");

		if (0 != mkdir(tmp.root, 0700))
			panic_m("%s", tmp.root);

		atexit(&rmtmpdir);

		if (0 != chdir(tmp.root))
			panic_m("chdir %s", tmp.root);
	} /* mktmpdir() */

	struct sockname {
		int flags;

		const char *type;
		const char *call;

		union {
			struct sockaddr sa;
			struct sockaddr_un sun;
			struct sockaddr_storage ss;
		} sa;
		socklen_t salen;

		struct {
			_Bool isset;
			int type;
			const char *text;
		} family;

		struct {
			_Bool defined;
			_Bool isset;
			_Bool empty;
			const char *text;
		} path;
	}; /* struct sockname */

	#define GETNAME_LISTENFD     0x01
	#define GETNAME_ACCEPTFD     0x02
	#define GETNAME_CONNECTFD    0x04
	#define GETNAME_SOCKETPAIRFD 0x08
	#define GETNAME_SOCKNAME     0x10
	#define GETNAME_PEERNAME     0x20

	static struct sockname getname(int fd, int flags) {
		struct sockname name;
		int ret;

		memset(&name, 0, sizeof name);
		name.flags = flags;
		name.type = (flags & GETNAME_CONNECTFD)? "connect" : (flags & GETNAME_ACCEPTFD)? "accept" : (flags & GETNAME_LISTENFD)? "listen" : "socketpair";
		name.call = (flags & GETNAME_PEERNAME)? "getpeername" : "getsockname";
		name.family.type = AF_UNSPEC;
		name.family.text = "unset";
		name.path.text = "-";

		name.salen = sizeof name.sa;

		if (flags & GETNAME_PEERNAME) {
			ret = getpeername(fd, (struct sockaddr *)&name.sa, &name.salen);
		} else {
			ret = getsockname(fd, (struct sockaddr *)&name.sa, &name.salen);
		}

		if (0 != ret)
			panic_m("%s", (flags & GETNAME_PEERNAME)? "getpeername" : "getsockname");

		if (name.salen >= offsetof(struct sockaddr_un, sun_family) + sizeof (name.sa.sun.sun_family)) {
			name.family.isset = 1;
			name.family.type = name.sa.sun.sun_family;

			switch (name.family.type) {
			case AF_UNSPEC:
				name.family.text = "AF_UNSPEC";
				break;
			case AF_UNIX:
				name.family.text = "AF_UNIX";
				break;
			default:
				name.family.text = "?";
				break;
			}
		}

		if (name.family.type == AF_UNIX) {
			name.path.defined = 1;

			if (name.salen > offsetof(struct sockaddr_un, sun_path)) {
				name.path.isset = 1;
				name.path.empty = 0 == strnlen(name.sa.sun.sun_path, sizeof name.sa.sun.sun_path);
				name.path.text = (name.path.empty)? "empty" : "set";
			} else {
				name.path.text = "unset";
			}
		}

		return name;
	} /* getname() */

	static void printname(struct sockname name) {
		printf("%-10s | %s | %-4d | %-9s | %-6s", name.type, name.call, (int)name.salen, name.family.text, name.path.text);
		if (name.path.isset && !name.path.empty)
			printf(" (%s)", name.sa.sun.sun_path);
		putchar('\n');
	} /* printname() */

	int main(void) {
		struct sockaddr_un sun, none;
		int listen_fd = -1, accept_fd = -1, connect_fd = -1, pair_fd[2] = { -1, -1 };
		int flags, i;
		struct sockname name[7];

		mktmpdir();

		if (-1 == (listen_fd = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)))
			panic_m("socket");
		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, tmp.name, sizeof sun.sun_path);
		if (0 != bind(listen_fd, (struct sockaddr *)&sun, sizeof sun))
			panic_m("bind %s", tmp.name);
		if (0 != listen(listen_fd, SOMAXCONN))
			panic_m("listen");
		name[0] = getname(listen_fd, GETNAME_LISTENFD|GETNAME_SOCKNAME);

		if (-1 == (connect_fd = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)))
			panic_m("socket");
		if (-1 == (flags = fcntl(connect_fd, F_GETFL)))
			panic_m("fcntl");
		if (0 != fcntl(connect_fd, F_SETFL, flags|O_NONBLOCK))
			panic_m("fcntl");
		memset(&sun, 0, sizeof sun);
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, tmp.name, sizeof sun.sun_path);
		(void)connect(connect_fd, (struct sockaddr *)&sun, sizeof sun);

		/* Minix segfaults when passing NULL */
		memset(&none, 0, sizeof none);
		if (-1 == (accept_fd = accept(listen_fd, (struct sockaddr *)&none, &(socklen_t){ sizeof none })))
			panic_m("accept");

		/*
		 * Minix requires that we connect asynchronously. All other systems
		 * completed the test with a synchrous connect followed by
		 * synchronous accept
		 */
		while (0 != connect(connect_fd, (struct sockaddr *)&sun, sizeof sun)) {
			if (errno == EALREADY || errno == EISCONN)
				break;
			if (errno != EINPROGRESS)
				panic_m("connect %s", tmp.name);
		}

		name[1] = getname(accept_fd, GETNAME_ACCEPTFD|GETNAME_SOCKNAME);
		name[2] = getname(accept_fd, GETNAME_ACCEPTFD|GETNAME_PEERNAME);
		name[3] = getname(connect_fd, GETNAME_CONNECTFD|GETNAME_SOCKNAME);
		name[4] = getname(connect_fd, GETNAME_CONNECTFD|GETNAME_PEERNAME);

		if (0 != socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair_fd))
			panic_m("socketpair");

		name[5] = getname(pair_fd[0], GETNAME_SOCKETPAIRFD|GETNAME_SOCKNAME);
		name[6] = getname(pair_fd[0], GETNAME_SOCKETPAIRFD|GETNAME_PEERNAME);

		for (i = 0; i < (int)(sizeof name / sizeof *name); i++)
			printname(name[i]);
		return 0;
	} /* main() */

---------------------------------------------------------------------------
