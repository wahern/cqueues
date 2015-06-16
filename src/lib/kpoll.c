/* ==========================================================================
 * kpoll.c - Brew of Linux epoll, BSD kqueue, and Solaris Ports.
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
#include <stddef.h>	/* NULL offsetof */

#include <string.h>	/* memset(3) */

#include <time.h>	/* struct timespec */

#include <errno.h>	/* errno */

#include <poll.h>	/* POLLIN POLLOUT */

#include <unistd.h>	/* [FEATURES] read(2) write(2) */

#ifndef __GLIBC_PREREQ
#define __GLIBC_PREREQ(m, n) 0
#endif

#ifndef HAVE_KQUEUE
#define HAVE_KQUEUE (__FreeBSD__ || __NetBSD__ || __OpenBSD__ || __APPLE__)
#endif

#ifndef HAVE_EPOLL
#define HAVE_EPOLL (__linux__)
#endif

#ifndef HAVE_PORTS
#define HAVE_PORTS (__sun)
#endif

#ifndef HAVE_EPOLL_CREATE1
#define HAVE_EPOLL_CREATE1 (HAVE_EPOLL && __GLIBC_PREREQ(2, 9))
#endif

#ifndef HAVE_PIPE2
#define HAVE_PIPE2 __GLIBC_PREREQ(2, 9)
#endif

#if HAVE_EPOLL
#include <sys/epoll.h>	/* struct epoll_event epoll_create(2) epoll_ctl(2) epoll_wait(2) */
#elif HAVE_PORTS
#include <port.h>	/* PORT_SOURCE_FD port_associate(2) port_disassociate(2) port_getn(2) port_alert(2) */
#else
#include <sys/event.h>	/* EVFILT_READ EVFILT_WRITE EV_SET EV_ADD EV_DELETE struct kevent kqueue(2) kevent(2) */
#endif

#include <sys/queue.h>	/* LIST_ENTRY LIST_HEAD LIST_REMOVE LIST_INSERT_HEAD */

#include <fcntl.h>	/* F_GETFL F_SETFL F_GETFD F_SETFD FD_CLOEXEC O_NONBLOCK O_CLOEXEC fcntl(2) */


#define KPOLL_MAXWAIT 32

#define countof(a) (sizeof (a) / sizeof *(a))

#if __GNUC__ >= 3
#define unlikely(expr) __builtin_expect((expr), 0)
#else
#define unlikely(expr) (expr)
#endif


static int setnonblock(int fd) {
	int flags;

	if (-1 == (flags = fcntl(fd, F_GETFL)))
		return errno;

	if (!(flags & O_NONBLOCK)) {
		if (-1 == fcntl(fd, F_SETFL, (flags | O_NONBLOCK)))
			return errno;
	}

	return 0;
} /* setnonblock() */


static int setcloexec(int fd) {
	int flags;

	if (-1 == (flags = fcntl(fd, F_GETFD)))
		return errno;

	if (!(flags & FD_CLOEXEC)) {
		if (-1 == fcntl(fd, F_SETFD, (flags | FD_CLOEXEC)))
			return errno;
	}

	return 0;
} /* setcloexec() */


static void closefd(int *fd) {
	if (*fd >= 0) {
		while (0 != close(*fd) && errno == EINTR)
			;;
		*fd = -1;
	}
} /* closefd() */


#if HAVE_EPOLL
typedef struct epoll_event event_t;
#elif HAVE_PORTS
typedef port_event_t event_t;
#else
/* NetBSD uses intptr_t while others use void * for .udata */
#define EV_SETx(ev, a, b, c, d, e, f) EV_SET((ev), (a), (b), (c), (d), (e), ((__typeof__((ev)->udata))(f)))

typedef struct kevent event_t;
#endif


static inline void *event_udata(const event_t *event) {
#if HAVE_EPOLL
	return event->data.ptr;
#elif HAVE_PORTS
	return event->portev_user;
#else
	return (void *)event->udata;
#endif
} /* event_udata() */


static inline short event_pending(const event_t *event) {
#if HAVE_EPOLL
	return event->events;
#elif HAVE_PORTS
	return event->portev_events;
#else
	return (event->filter == EVFILT_READ)? POLLIN : (event->filter == EVFILT_WRITE)? POLLOUT : 0;
#endif
} /* event_pending() */


struct kpollfd {
	int fd;
	short events;
	short revents;
	LIST_ENTRY(kpollfd) le;
}; /* struct kpollfd */


struct kpoll {
	int fd;

	LIST_HEAD(, kpollfd) pending;
	LIST_HEAD(, kpollfd) polling;
	LIST_HEAD(, kpollfd) dormant;

	struct {
		struct kpollfd event;
		int fd[2];
	} alert;
}; /* struct kpoll */


static void kpoll_move(struct kpoll *kp, struct kpollfd *fd) {
	LIST_REMOVE(fd, le);

	if (fd->revents)
		LIST_INSERT_HEAD(&kp->pending, fd, le);
	else if (fd->events)
		LIST_INSERT_HEAD(&kp->polling, fd, le);
	else
		LIST_INSERT_HEAD(&kp->dormant, fd, le);
} /* kpoll_move() */


static struct kpollfd *kpoll_next(struct kpoll *kp) {
	return LIST_FIRST(&kp->pending);
} /* kpoll_next() */


static int kpoll_ctl(struct kpoll *kp, struct kpollfd *fd, short events) {
	int error = 0;

	if (fd->events == events)
		goto reset;

#if HAVE_EPOLL
	struct epoll_event event;
	int op;

	op = (!fd->events)? EPOLL_CTL_ADD : (!events)? EPOLL_CTL_DEL : EPOLL_CTL_MOD;

	memset(&event, 0, sizeof event);

	event.events = events;
	event.data.ptr = fd;

	if (0 != epoll_ctl(kp->fd, op, fd->fd, &event))
		goto error;

	fd->events = events;
#elif HAVE_PORTS
	if (!events) {
		if (0 != port_dissociate(kp->fd, PORT_SOURCE_FD, fd->fd))
			goto error;
	} else {
		if (0 != port_associate(kp->fd, PORT_SOURCE_FD, fd->fd, events, fd))
			goto error;
	}

	fd->events = events;
#else
	struct kevent event;

	if (events & POLLIN) {
		if (!(fd->events & POLLIN)) {
			EV_SETx(&event, fd->fd, EVFILT_READ, EV_ADD, 0, 0, fd);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				goto error;

			fd->events |= POLLIN;
		}
	} else if (fd->events & POLLIN) {
		EV_SETx(&event, fd->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

		if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			goto error;

		fd->events &= ~POLLIN;
	}

	if (events & POLLOUT) {
		if (!(fd->events & POLLOUT)) {
			EV_SETx(&event, fd->fd, EVFILT_WRITE, EV_ADD, 0, 0, fd);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				goto error;

			fd->events |= POLLOUT;
		}
	} else if (fd->events & POLLOUT) {
		EV_SETx(&event, fd->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

		if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			goto error;

		fd->events &= ~POLLOUT;
	}
#endif

reset:
	fd->revents = 0;

	kpoll_move(kp, fd);

	return error;
error:
	error = errno;

	goto reset;
} /* kpoll_ctl() */


static void kpoll_add(struct kpoll *kp, struct kpollfd *pfd, int fd) {
	pfd->fd = fd;
	pfd->events = 0;
	pfd->revents = 0;

	LIST_INSERT_HEAD(&kp->dormant, pfd, le);
} /* kpoll_add() */


static void kpoll_del(struct kpoll *kp, struct kpollfd *fd) {
	kpoll_ctl(kp, fd, 0);

	LIST_REMOVE(fd, le);
} /* kpoll_del() */


static int kpoll_alert(struct kpoll *kp) {
#if HAVE_PORTS
	return (!port_alert(kp->fd, PORT_ALERT_SET, POLLIN, &kp->alert.event))? 0 : errno;
#else
	while (1 != write(kp->alert.fd[1], "!", 1)) {
		switch (errno) {
		case EINTR:
			continue;
		case EAGAIN:
			return 0;
		default:
			return errno;
		}
	}

	return kpoll_ctl(kp, &kp->alert.event, POLLIN);
#endif
} /* kpoll_alert() */


static int kpoll_calm(struct kpoll *kp) {
#if HAVE_PORTS
	return (!port_alert(kp->fd, PORT_ALERT_SET, 0, &kp->alert.event))? 0 : errno;
#else
	char buf[512];

	while (read(kp->alert.fd[0], buf, sizeof buf) > 0)
		;;

	return kpoll_ctl(kp, &kp->alert.event, POLLIN);
#endif
} /* kpoll_calm() */


static inline struct timespec *ms2ts_(struct timespec *ts, int ms) {
	if (ms < 0) return 0;
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000000;
	return ts;
} /* ms2ts_() */

#define ms2ts(ms) (ms2ts_(&(struct timespec){ 0, 0 }, (ms)))


static int kpoll_wait(struct kpoll *kp, int timeout) {
	event_t event[KPOLL_MAXWAIT];
	struct kpollfd *fd;
	int error;

	if (!LIST_EMPTY(&kp->pending))
		return 0;

#if HAVE_EPOLL
	int i, n;

	if (-1 == (n = epoll_wait(kp->fd, event, (int)countof(event), timeout)))
		return (errno == EINTR)? 0 : errno;
#elif HAVE_PORTS
	uint_t i, n = 1;

	if (0 != port_getn(kp->fd, event, countof(event), &n, ms2ts(timeout)))
		return (errno == ETIME || errno == EINTR)? 0 : errno;
#else
	int i, n;

	if (-1 == (n = kevent(kp->fd, NULL, 0, event, (int)countof(event), ms2ts(timeout))))
		return (errno == EINTR)? 0 : errno;
#endif

	for (i = 0; i < n; i++) {
		fd = event_udata(&event[i]);
#if HAVE_PORTS
		fd->events = 0;
#endif

		if (unlikely(fd == &kp->alert.event)) {
			if ((error = kpoll_calm(kp)))
				return error;
		} else {
			fd->revents |= event_pending(&event[i]);
			kpoll_move(kp, fd);
		}
	}

	return 0;
} /* kpoll_wait() */


static int alert_init(struct kpoll *kp) {
#if HAVE_PORTS
	return 0;
#else
	int error;

#if HAVE_PIPE2
	if (0 != pipe2(kp->alert.fd, O_CLOEXEC|O_NONBLOCK))
		return errno;
#else
	if (0 != pipe(kp->alert.fd))
		return errno;

	for (int i = 0; i < 2; i++) {
		if ((error = setcloexec(kp->alert.fd[i]))
		||  (error = setnonblock(kp->alert.fd[i])))
			return error;
	}
#endif

	kpoll_add(kp, &kp->alert.event, kp->alert.fd[0]);

	return kpoll_ctl(kp, &kp->alert.event, POLLIN);
#endif
} /* alert_init() */


static void alert_destroy(struct kpoll *kp) {
#if HAVE_PORTS
	(void)0;
#else
	closefd(&kp->alert.fd[0]);
	closefd(&kp->alert.fd[1]);
#endif
} /* alert_destroy() */


static void kpoll_destroy(struct kpoll *kp) {
	closefd(&kp->fd);

	alert_destroy(kp);

	LIST_INIT(&kp->pending);
	LIST_INIT(&kp->polling);
	LIST_INIT(&kp->dormant);
} /* kpoll_destroy() */


static int kpoll_init(struct kpoll *kp) {
	int error;

	kp->fd = -1;
	kp->alert.fd[0] = -1;
	kp->alert.fd[1] = -1;

	LIST_INIT(&kp->pending);
	LIST_INIT(&kp->polling);
	LIST_INIT(&kp->dormant);

#if HAVE_EPOLL_CREATE1
	if (-1 == (kp->fd = epoll_create1(O_CLOEXEC)))
		goto syerr;
#elif HAVE_EPOLL
	if (-1 == (kp->fd = epoll_create(0)))
		goto syerr;
#elif HAVE_PORTS
	if (-1 == (kp->fd = port_create())) {
		if (errno == EAGAIN) { /* too confusing */
			error = EMFILE;
			goto error;
		} else
			goto syerr;
	}
#else
	if (-1 == (kp->fd = kqueue()))
		goto syerr;
#endif

#if !HAVE_EPOLL_CREATE1
	if ((error = setcloexec(kp->fd)))
		goto error;
#endif

	if ((error = alert_init(kp)))
		goto error;

	return 0;
syerr:
	error = errno;
error:
	kpoll_destroy(kp);

	return error;
} /* kpoll_init() */


int main(void) {
	return 0;
}
