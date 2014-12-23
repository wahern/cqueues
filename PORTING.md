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

## APPENDIX

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
