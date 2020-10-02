/* ==========================================================================
 * cqueues.c - Lua Continuation Queues
 * --------------------------------------------------------------------------
 * Copyright (c) 2012-2015  William Ahern
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
#include "config.h"

#include <limits.h>	/* INT_MAX LONG_MAX */
#include <float.h>	/* FLT_RADIX */
#include <stdarg.h>	/* va_list va_start va_end */
#include <stddef.h>	/* NULL offsetof() size_t */
#include <stdlib.h>	/* malloc(3) free(3) */
#include <string.h>	/* memset(3) */
#include <signal.h>	/* sigprocmask(2) pthread_sigmask(3) */
#include <time.h>	/* struct timespec clock_gettime(3) */
#include <math.h>	/* FP_* NAN fmax(3) fpclassify(3) isfinite(3) signbit(3) islessequal(3) isgreater(3) ceil(3) modf(3) */
#include <errno.h>	/* errno */
#include <assert.h>	/* assert */

#include <sys/queue.h>	/* LIST_* TAILQ_* */
#include <sys/time.h>	/* struct timeval */
#include <sys/select.h>	/* pselect(3) */
#include <unistd.h>	/* close(2) */
#include <fcntl.h>	/* F_SETFD FD_CLOEXEC fcntl(2) */
#include <poll.h>	/* POLLIN POLLOUT POLLPRI */

#include <lua.h>
#include <lauxlib.h>

#include "lib/llrb.h"
#include "cqueues.h"


/*
 * V E R S I O N  I N T E R F A C E S
 *
 * If forking change CQUEUES_VENDOR to avoid confusion.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef CQUEUES_VENDOR
#define CQUEUES_VENDOR "william@25thandClement.com"
#endif

#ifndef CQUEUES_VERSION
#define CQUEUES_VERSION 20161215L
#endif


/*
 * D E B U G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !defined SAY
#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")
#endif

#if __GNUC__
#define NOTUSED __attribute__((unused))
#else
#define NOTUSED
#endif

#if (__GNUC__ == 4 && __GNUC_MINOR__ >= 5) || __GNUC__ > 4 || __clang__
#define NOTREACHED __builtin_unreachable()
#else
#define NOTREACHED (void)0
#endif

#if __GNUC__
#define NONNULL(...) __attribute__((nonnull (__VA_ARGS__)))
#else
#define NONNULL(...)
#endif

#if __GNUC__
#define luaL_error(...) __extension__ ({ int tmp = luaL_error(__VA_ARGS__); NOTREACHED; tmp; })
#endif


/*
 * U T I L I T Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

inline static int setcloexec(int fd) {
	if (-1 == fcntl(fd, F_SETFD, FD_CLOEXEC))
		return errno;

	return 0;
} /* setcloexec() */


/*
 * T I M E  &  C L O C K  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * clock_gettime()
 *
 * OS X didn't implement the clock_gettime() POSIX interface until macOS
 * 10.12 (Sierra). But it did provide a monotonic clock through
 * mach_absolute_time(). On i386 and x86_64 architectures this clock is in
 * nanosecond units, but not so on other devices. mach_timebase_info()
 * provides the conversion parameters.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#if __APPLE__

#include <errno.h>           /* errno EINVAL */
#include <time.h>            /* struct timespec */

#include <sys/time.h>        /* TIMEVAL_TO_TIMESPEC struct timeval gettimeofday(3) */

#include <mach/mach_time.h>  /* mach_timebase_info_data_t mach_timebase_info() mach_absolute_time() */

#if !HAVE_DECL_CLOCK_REALTIME
enum { CLOCK_REALTIME = 0 };
#endif
#if !HAVE_DECL_CLOCK_MONOTONIC
enum { CLOCK_MONOTONIC = 6 };
#endif

#if !HAVE_CLOCKID_T
typedef int clockid_t;
#endif

#if HAVE_CLOCK_GETTIME && !HAVE_DECL_CLOCK_GETTIME
extern int (clock_gettime)(clockid_t, struct timespec *);
#endif

static mach_timebase_info_data_t clock_timebase = {
	.numer = 1, .denom = 1,
}; /* clock_timebase */

static int compat_clock_gettime(clockid_t clockid, struct timespec *ts) {
	switch (clockid) {
	case CLOCK_REALTIME: {
		struct timeval tv;

		if (0 != gettimeofday(&tv, 0))
			return -1;

		TIMEVAL_TO_TIMESPEC(&tv, ts);

		return 0;
	}
	case CLOCK_MONOTONIC: {
		unsigned long long abt;

		abt = mach_absolute_time();
		abt = abt * clock_timebase.numer / clock_timebase.denom;

		ts->tv_sec = abt / 1000000000UL;
		ts->tv_nsec = abt % 1000000000UL;

		return 0;
	}
	default:
		errno = EINVAL;

		return -1;
	} /* switch() */
} /* clock_gettime() */

#define clock_gettime(clockid, ts) clock_gettime_p((clockid), (ts))

static int (*clock_gettime_p)(clockid_t, struct timespec *) = &compat_clock_gettime;

void clock_gettime_init(void) __attribute__((constructor));

void clock_gettime_init(void) {
#if HAVE_CLOCK_GETTIME
	/*
	 * NB: clock_gettime is implemented as a weak symbol which autoconf
	 * tests will always positively identify when compiling with XCode
	 * 8.0 or above, regardless of -mmacosx-version-min. Similarly, it
	 * will always be declared by XCode 8.0 or above.
	 */
	if (&(clock_gettime)) {
		clock_gettime_p = &(clock_gettime);
		return;
	}
#endif
	if (mach_timebase_info(&clock_timebase) != KERN_SUCCESS)
		__builtin_abort();

	clock_gettime_p = &compat_clock_gettime;
} /* clock_gettime_init() */

#endif /* __APPLE__ */


static inline int f2ms(const double f) {
	double ms;

	switch (fpclassify(f)) {
	case FP_NORMAL:
		if (signbit(f))
			return 0;

		ms = ceil(f * 1000);

		return (ms > INT_MAX)? INT_MAX : ms;
	case FP_SUBNORMAL:
		return 1;
	case FP_ZERO:
		return 0;
	case FP_INFINITE:
	case FP_NAN:
	default:
		return -1;
	}
} /* f2ms() */

static inline struct timespec *f2ts_(struct timespec *ts, const double f) {
	double s, ns;

	switch (fpclassify(f)) {
	case FP_NORMAL:
		if (signbit(f))
			return ts;

		ns = modf(f, &s);
		ns = ceil(ns * 1000000000);

		if (ns >= 1000000000) {
			s++;
			ns = 0;
		}

		cqs_static_assert(FLT_RADIX == 2, "FLT_RADIX != 2");
		cqs_static_assert(cqs_ispowerof2((unsigned long)LONG_MAX + 1), "LONG_MAX + 1 not a power of 2");

		if (s >= (unsigned long)LONG_MAX + 1) {
			ts->tv_sec = LONG_MAX;
			ts->tv_nsec = 0;
		} else {
			ts->tv_sec = s;
			ts->tv_nsec = ns;
		}

		return ts;
	case FP_SUBNORMAL:
		ts->tv_sec = 0;
		ts->tv_nsec = 1;

		return ts;
	case FP_ZERO:
		return ts;
	case FP_INFINITE:
	case FP_NAN:
	default:
		return NULL;
	}
} /* f2ts_() */

#define f2ts(f) f2ts_(&(struct timespec){ 0, 0 }, (f))


static inline double ts2f(const struct timespec *ts) {
	return ts->tv_sec + (ts->tv_nsec / 1000000000.0);
} /* ts2f() */


static inline double tv2f(const struct timeval *tv) {
	return tv->tv_sec + (tv->tv_usec / 1000000.0);
} /* tv2f() */


static inline double monotime(void) {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts2f(&ts);
} /* monotime() */


static inline double abstimeout(double timeout) {
	return (isfinite(timeout))? monotime() + fmax(timeout, 0) : NAN;
} /* abstimeout() */


static inline double reltimeout(double timeout) {
	double curtime;

	if (!isfinite(timeout))
		return NAN;

	curtime = monotime();

	return (islessequal(timeout, curtime))? 0.0 : timeout - curtime;
} /* reltimeout() */


static inline double mintimeout(double a, double b) {
	if (islessequal(a, b) || !isfinite(b))
		return a;
	else if (islessequal(b, a) || !isfinite(a))
		return b;
	else
		return NAN;
} /* mintimeout() */


/*
 * M E M O R Y  M A N A G M E N T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void *make(size_t size, int *error) {
	void *p;

	if (!(p = malloc(size)))
		*error = errno;

	return p;
} /* make() */


struct pool {
	size_t size, count;
	void *head;
}; /* pool */

static void pool_init(struct pool *P, size_t size) {
	P->size  = MAX(size, sizeof (void **));
	P->count = 0;
	P->head  = NULL;
} /* pool_init() */

static void pool_destroy(struct pool *P) {
	void *p;

	while ((p = P->head)) {
		P->head = *(void **)p;
		free(p);
		P->count--;
	}
} /* pool_destroy() */

static void pool_put(struct pool *P, void *p) {
	*(void **)p = P->head;
	P->head = p;
} /* pool_put() */

static int pool_grow(struct pool *P, size_t n) {
	void *p;
	int error;

	while (n--) {
		if (P->count + 1 == 0)
			return ENOMEM;

		if (!(p = make(P->size, &error)))
			return error;

		P->count++;

		pool_put(P, p);
	}

	return 0;
} /* pool_grow() */

static void *pool_get(struct pool *P, int *_error) {
	void *p;
	int error;

	if (!(p = P->head)) {
		error = pool_grow(P, MAX(1, P->count));

		if (!(p = P->head)) {
			*_error = error;

			return NULL;
		}
	}

	P->head = *(void **)p;

	return p;
} /* pool_get() */


/*
 * K P O L L  ( K Q U E U E / E P O L L )  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if ENABLE_EPOLL
#include <sys/epoll.h>	/* struct epoll_event epoll_create(2) epoll_ctl(2) epoll_wait(2) */
#elif ENABLE_PORTS
#include <port.h>
#elif ENABLE_KQUEUE
#include <sys/event.h>	/* EVFILT_READ EVFILT_WRITE EV_SET EV_ADD EV_DELETE struct kevent kqueue(2) kevent(2) */
#else
#error "No polling backend available"
#endif

#if HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h> /* eventfd(2) */
#endif


#define KPOLL_FOREACH(ke, kp) for (ke = (kp)->pending.event; ke < &(kp)->pending.event[(kp)->pending.count]; ke++)

#define KPOLL_MAXWAIT 32

#if ENABLE_EPOLL
typedef struct epoll_event kpoll_event_t;
#elif ENABLE_PORTS
typedef port_event_t kpoll_event_t;
#elif ENABLE_KQUEUE
/* NetBSD uses intptr_t, others use void *, for .udata */
#define KP_P2UDATA(p) ((__typeof__(((struct kevent *)0)->udata))(p))
#define KP_UDATA2P(udata) ((void *)(udata))
#define KP_SET(ev, a, b, c, d, e, f) EV_SET((ev), (a), (b), (c), (d), (e), KP_P2UDATA(f))

typedef struct kevent kpoll_event_t;
#endif

struct kpoll {
	int fd;

	struct {
		kpoll_event_t *event;
		size_t events_allocated;
		size_t count;
	} pending;

	struct {
		int fd[2];
		short state;
		int pending;
	} alert;
}; /* struct kpoll */


static void kpoll_preinit(struct kpoll *kp) {
	kp->fd = -1;
	kp->pending.event = NULL;
	kp->pending.events_allocated = 0;
	kp->pending.count = 0;
	for (size_t i = 0; i < countof(kp->alert.fd); i++)
		kp->alert.fd[i] = -1;
	kp->alert.state = 0;
	kp->alert.pending = 0;
} /* kpoll_preinit() */


static int kpoll_ctl(struct kpoll *, int, short *, short, void *);
static int alert_rearm(struct kpoll *);

static int alert_init(struct kpoll *kp) {
#if ENABLE_PORTS
	(void)kp;
	return 0;
#elif HAVE_EVENTFD
	if (kp->alert.fd[0] != -1)
		return 0;

	if (-1 == (kp->alert.fd[0] = eventfd(0, O_CLOEXEC|O_NONBLOCK)))
		return errno;

	return alert_rearm(kp);
#else
	int error;

	if (kp->alert.fd[0] != -1)
		return 0;

	if ((error = cqs_pipe(kp->alert.fd, O_CLOEXEC|O_NONBLOCK)))
		return error;

	return alert_rearm(kp);
#endif
} /* alert_init() */

static void alert_destroy(struct kpoll *kp, int (*closefd)(int *, void *), void *cb_udata) {
#if ENABLE_PORTS
	(void)kp;
#else
	for (size_t i = 0; i < countof(kp->alert.fd); i++)
		closefd(&kp->alert.fd[i], cb_udata);
#endif
} /* alert_destroy() */

static int alert_rearm(struct kpoll *kp) {
#if ENABLE_PORTS
	return 0;
#else
	return kpoll_ctl(kp, kp->alert.fd[0], &kp->alert.state, POLLIN, &kp->alert);
#endif
} /* alert_rearm() */


static int kpoll_init(struct kpoll *kp) {
	int error;

	kp->pending.event = calloc(KPOLL_MAXWAIT, sizeof(kpoll_event_t));
	if (NULL == kp->pending.event)
		return ENOMEM;
	kp->pending.events_allocated = KPOLL_MAXWAIT;

#if ENABLE_EPOLL
#if defined EPOLL_CLOEXEC
	(void)error;
	if (-1 == (kp->fd = epoll_create1(EPOLL_CLOEXEC)))
		return errno;
#else
	if (-1 == (kp->fd = epoll_create(32)))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;
#endif
#elif ENABLE_PORTS
	if (-1 == (kp->fd = port_create()))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;
#elif ENABLE_KQUEUE
	if (-1 == (kp->fd = kqueue()))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;
#endif

	return alert_init(kp);
} /* kpoll_init() */


static void kpoll_destroy(struct kpoll *kp, int (*closefd)(int *, void *), void *cb_udata) {
	alert_destroy(kp, closefd, cb_udata);
	closefd(&kp->fd, cb_udata);
	free(kp->pending.event);
	kpoll_preinit(kp);
} /* kpoll_destroy() */


static inline void *kpoll_udata(const kpoll_event_t *event) {
#if ENABLE_EPOLL
	return event->data.ptr;
#elif ENABLE_PORTS
	return event->portev_user;
#elif ENABLE_KQUEUE
	return KP_UDATA2P(event->udata);
#endif
} /* kpoll_udata() */


static inline short kpoll_pending(const kpoll_event_t *event) {
#if ENABLE_EPOLL
	return event->events;
#elif ENABLE_PORTS
	return event->portev_events;
#elif ENABLE_KQUEUE
	return (event->filter == EVFILT_READ)? POLLIN : (event->filter == EVFILT_WRITE)? POLLOUT : 0;
#endif
} /* kpoll_pending() */


static inline short kpoll_diff(const kpoll_event_t *event NOTUSED, short ostate NOTUSED) {
#if ENABLE_PORTS
	/* Solaris Event Ports aren't persistent. */
	return 0;
#else
	return ostate;
#endif
} /* kpoll_diff() */


static int kpoll_ctl(struct kpoll *kp, int fd, short *state, short events, void *udata) {
#if ENABLE_EPOLL
	struct epoll_event event;
	int op;

	if (*state == events)
		return 0;

	op = (!*state)? EPOLL_CTL_ADD : (!events)? EPOLL_CTL_DEL : EPOLL_CTL_MOD;

	memset(&event, 0, sizeof event);

	event.events = events;
	event.data.ptr = udata;

	if (0 != epoll_ctl(kp->fd, op, fd, &event))
		return errno;

	*state = events;

	return 0;
#elif ENABLE_PORTS
	if (*state == events)
		return 0;

	if (!events) {
		if (0 != port_dissociate(kp->fd, PORT_SOURCE_FD, fd))
			return errno;
	} else {
		if (0 != port_associate(kp->fd, PORT_SOURCE_FD, fd, events, udata))
			return errno;
	}

	*state = events;

	return 0;
#elif ENABLE_KQUEUE
	struct kevent event;

	if (*state == events)
		return 0;

	if (events & POLLIN) {
		if (!(*state & POLLIN)) {
			KP_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, udata);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				return errno;

			*state |= POLLIN;
		}
	} else if (*state & POLLIN) {
		KP_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

		if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			return errno;

		*state &= ~POLLIN;
	}

	if (events & POLLOUT) {
		if (!(*state & POLLOUT)) {
			KP_SET(&event, fd, EVFILT_WRITE, EV_ADD, 0, 0, udata);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				return errno;

			*state |= POLLOUT;
		}
	} else if (*state & POLLOUT) {
		KP_SET(&event, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

		if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			return errno;

		*state &= ~POLLOUT;
	}

	return 0;
#endif
} /* kpoll_ctl() */


static int kpoll_alert(struct kpoll *kp) {
	int error;

	if (kp->alert.pending)
		return 0;

	/* initialization may have been delayed */
	if ((error = alert_init(kp)))
		return error;
#if ENABLE_PORTS
	if (0 != port_send(kp->fd, POLLIN, &kp->alert)) {
		if (errno != EBUSY)
			return errno;
	}
#elif HAVE_EVENTFD
	static const uint64_t one = 1;

	while (-1 == write(kp->alert.fd[0], &one, sizeof one)) {
		if (errno == EAGAIN) {
			break;
		} else if (errno != EINTR) {
			return errno;
		}
	}
#else
	while (-1 == write(kp->alert.fd[1], "!", 1)) {
		if (errno == EAGAIN) {
			break;
		} else if (errno != EINTR) {
			return errno;
		}
	}
#endif
	if ((error = alert_rearm(kp)))
		return error;

	kp->alert.pending = 1;

	return 0;
} /* kpoll_alert() */


static int kpoll_calm(struct kpoll *kp) {
	int error;

#if ENABLE_PORTS
	/* each PORT_SOURCE_USER event is discrete */
#elif HAVE_EVENTFD
	uint64_t n;

	while (-1 == read(kp->alert.fd[0], &n, sizeof n)) {
		if (errno == EAGAIN) {
			break;
		} else if (errno != EINTR) {
			return errno;
		}
	}
#else
	for (;;) {
		char buf[64];
		ssize_t n;

		if (-1 == (n = read(kp->alert.fd[0], buf, sizeof buf))) {
			if (errno == EAGAIN) {
				break;
			} else if (errno != EINTR) {
				return errno;
			}
		} else if (n == 0) {
			return EPIPE; /* somebody closed our fd! */
		}
	}
#endif
	if ((error = alert_rearm(kp)))
		return error;

	kp->alert.pending = 0;

	return 0;
} /* kpoll_calm() */


static inline short kpoll_isalert(struct kpoll *kp, const kpoll_event_t *event) {
#if ENABLE_PORTS
	return event->portev_source == PORT_SOURCE_USER;
#else
	return kpoll_udata(event) == &kp->alert;
#endif
} /* kpoll_isalert() */


static int kpoll_wait(struct kpoll *kp, double timeout) {
	kpoll_event_t *result = kp->pending.event;
	size_t max_events = kp->pending.events_allocated;

	kp->pending.count = 0;

	while (1) {
#if ENABLE_EPOLL
		int n;

		if (-1 == (n = epoll_wait(kp->fd, result, (int)max_events, f2ms(timeout))))
			return (errno == EINTR)? 0 : errno;
#elif ENABLE_PORTS
		uint_t n = 1;

		if (0 != port_getn(kp->fd, result, max_events, &min_events, f2ts(timeout)))
			return (errno == ETIME || errno == EINTR)? 0 : errno;
#elif ENABLE_KQUEUE
		int n;

		if (-1 == (n = kevent(kp->fd, NULL, 0, result, (int)max_events, f2ts(timeout))))
			return (errno == EINTR)? 0 : errno;
#endif

		kp->pending.count += n;

		if ((size_t)n < max_events)
			break;

		/* If max events was reached, try and get more events: use no timeout. */
		/* prevent overflow on multiply below */
		if (kp->pending.events_allocated >= ((__SIZE_MAX__>>2)/sizeof(kpoll_event_t)))
			return EOVERFLOW;
		/* multiply by 4 as events may be level-triggered and hence we'll get them again */
		size_t newsize = kp->pending.events_allocated << 2;
		void *tmp;
		if (NULL == (tmp = realloc(kp->pending.event, newsize*sizeof(kpoll_event_t))))
			return ENOMEM;
		kp->pending.events_allocated = newsize;
		kp->pending.event = tmp;
		result = kp->pending.event + kp->pending.count;
		max_events = kp->pending.events_allocated - kp->pending.count;
	}

	return 0;
} /* kpoll_wait() */


/*
 * A U X I L I A R Y  L I B R A R Y  R O U T I N E S
 *
 * Routines which can be used to improve integration, including extending
 * Lua's support for implicit yielding.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if LUA_VERSION_NUM >= 502
LUA_KFUNCTION(auxlib_tostringk) {
	if (luaL_getmetafield(L, 1, "__tostring")) {
		lua_pushfstring(L, "%s: %p", luaL_typename(L, 1), lua_topointer(L, 1));
	} else {
		luaL_tolstring(L, 1, NULL);
	}

	return 1;
} /* auxlib_tostringk() */

static int auxlib_tostring(lua_State *L) {
	luaL_checkany(L, 1);

	if (luaL_getmetafield(L, 1, "__tostring")) {
		lua_insert(L, 1);
		lua_settop(L, 2);
		lua_callk(L, 1, 1, 0, &auxlib_tostringk);

		return auxlib_tostringk(L, LUA_OK, 0);
	} else {
		luaL_tolstring(L, 1, NULL);

		return 1;
	}
} /* auxlib_tostring() */
#endif


static const luaL_Reg auxlib_globals[] = {
#if LUA_VERSION_NUM >= 502
	{ "tostring", &auxlib_tostring },
#endif
	{ NULL,       NULL }
}; /* auxlib_globals[] */


int luaopen__cqueues_auxlib(lua_State *L) {
	luaL_newlib(L, auxlib_globals);

	return 1;
} /* luaopen__cqueues_auxlib() */


/*
 * C O N D I T I O N  V A R I A B L E  R O U T I N E S
 *
 * FIXME: Add logic to the scheduler that prevents two coroutines from
 * continually placing each other onto the pending queue within the same
 * resume iteration. Otherwise cqueue_process could loop forever, starving
 * other contexts.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define wakecb_init(cb, ...) wakecb_init4((cb), __VA_ARGS__, NULL, NULL)
#define wakecb_init4(cb, _fn, a, b, ...) do { \
	(cb)->cv = NULL; \
	(cb)->fn = (_fn); \
	(cb)->arg[0] = (a); \
	(cb)->arg[1] = (b); \
} while (0)


struct wakecb {
	struct condition *cv;

	cqs_error_t (*fn)(struct wakecb *);
	void *arg[3];

	TAILQ_ENTRY(wakecb) tqe;
}; /* struct wakecb */


struct condition {
	_Bool lifo;

	TAILQ_HEAD(, wakecb) waiting;
}; /* struct condition */


static void wakecb_del(struct wakecb *cb) {
	if (cb->cv) {
		TAILQ_REMOVE(&cb->cv->waiting, cb, tqe);
		cb->cv = NULL;
	}
} /* wakecb_del() */


static void wakecb_add(struct wakecb *cb, struct condition *cv) {
	if (cv->lifo) {
		TAILQ_INSERT_HEAD(&cv->waiting, cb, tqe);
		cb->cv = cv;
	} else {
		TAILQ_INSERT_TAIL(&cv->waiting, cb, tqe);
		cb->cv = cv;
	}
} /* wakecb_add() */


static struct condition *cond_testself(lua_State *L, int index) {
	return cqs_testudata(L, index, 1);
} /* cond_testself() */


static struct condition *cond_checkself(lua_State *L, int index) {
	return cqs_checkudata(L, index, 1, CQS_CONDITION);
} /* cond_checkself() */


static int cond_type(lua_State *L) {
	if (cond_testself(L, 1)) {
		lua_pushstring(L, "condition");
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* cond_type() */


static int cond_interpose(lua_State *L) {
	return cqs_interpose(L, CQS_CONDITION);
} /* cond_interpose() */


static int cond_new(lua_State *L) {
	_Bool lifo = lua_toboolean(L, 1);
	struct condition *cv;

	cv = lua_newuserdata(L, sizeof *cv);
	cv->lifo = lifo;
	TAILQ_INIT(&cv->waiting);
	luaL_setmetatable(L, CQS_CONDITION);

	return 1;
} /* cond_new() */


static int cond__call(lua_State *L NOTUSED) {
	lua_settop(L, 1);

	return 1;
} /* cond__call() */


static int cond__gc(lua_State *L) {
	struct condition *cv = cond_checkself(L, 1);
	int empty = TAILQ_EMPTY(&cv->waiting);
	struct wakecb *cb;

	while ((cb = TAILQ_FIRST(&cv->waiting))) {
		wakecb_del(cb);
		/*
		 * NOTE: We drop wakeup callback errors. Throwing from a
		 * __gc metamethod seems less than useful. Applications can
		 * and should check errors when explicitly signaling. That
		 * we signal on GC is just a backstop for code that is
		 * already probably buggy.
		 */
		cb->fn(cb);
	}

	/*
	 * XXX: Check can fail when lua_State is destroyed (e.g. script
	 * terminates) and there are coroutines still waiting.  Condition
	 * variables are usually younger than the coroutines and objects
	 * waiting on them, resources are collected in reverse order of
	 * creation during each cycle, and in this case everything is
	 * collected in the same cycle.
	 *
	 * Note that even if luaL_error triggers, oddly the Lua interpreter
	 * will only show the message if the script terminated with an
	 * error, and not if it terminated normally.  The order of
	 * destruction is the same either way.
	 *
	 * Is there a way to detect that the lua_State is being destroyed?
	 */
	if (0 && !empty)
		return luaL_error(L, "invariant failure: condition variable wait queue not empty on __gc");

	return 0;
} /* cond__gc() */


static int cond_wait(lua_State *L) {
	cond_checkself(L, 1);

	lua_pushlightuserdata(L, CQUEUE__POLL);
	lua_insert(L, 1);

	return lua_yield(L, lua_gettop(L));
} /* cond_wait() */


static int cond_signal(lua_State *L) {
	struct condition *cv = cond_checkself(L, 1);
	int i, n = luaL_optint(L, 2, INT_MAX);
	struct wakecb *cb;
	int error;

	for (i = 0; i < n && !TAILQ_EMPTY(&cv->waiting); i++) {
		cb = TAILQ_FIRST(&cv->waiting);
		wakecb_del(cb);

		if ((error = cb->fn(cb)))
			goto error;
	}

	lua_pushinteger(L, i);

	return 1;
error:
	lua_pushnil(L);
	lua_pushstring(L, cqs_strerror(error));
	lua_pushinteger(L, error);

	return 3;
} /* cond_signal() */


static int cond_pollfd(lua_State *L) {
	cond_checkself(L, 1);
	lua_settop(L, 1);

	return 1;
} /* cond_pollfd() */


static int cond_events(lua_State *L NOTUSED) {
	return 0;
} /* cond_events() */


static int cond_timeout(lua_State *L NOTUSED) {
	return 0;
} /* cond_timeout() */


static const luaL_Reg cond_methods[] = {
	{ "wait",    &cond_wait },
	{ "signal",  &cond_signal },
	{ "pollfd",  &cond_pollfd },
	{ "events",  &cond_events },
	{ "timeout", &cond_timeout },
	{ NULL,      NULL }
}; /* cond_methods[] */


static const luaL_Reg cond_metatable[] = {
	{ "__call", &cond__call },
	{ "__gc",   &cond__gc },
	{ NULL,     NULL }
}; /* cond_metatable[] */


static const luaL_Reg cond_globals[] = {
	{ "new",       &cond_new },
	{ "type",      &cond_type },
	{ "interpose", &cond_interpose },
	{ NULL,        NULL }
}; /* cond_globals[] */


int luaopen__cqueues_condition(lua_State *L) {
	lua_pushnil(L); /* initial upvalue */
	cqs_newmetatable(L, CQS_CONDITION, cond_methods, cond_metatable, 1);
	lua_pushvalue(L, -1); /* push self as replacement upvalue */
	cqs_setmetaupvalue(L, -2, 1); /* insert self as 1st upvalue  */

	/* capture metatable here, too. */
	luaL_newlibtable(L, cond_globals);
	lua_pushvalue(L, -2);
	luaL_setfuncs(L, cond_globals, 1);

	return 1;
} /* luaopen__cqueues_condition() */


/*
 * C O N T I N U A T I O N  Q U E U E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define CQUEUE_CLASS "Continuation Queue"

const char *cqueue__poll = "poll magic"; // signals multilevel yield

typedef int auxref_t;

struct event;
struct thread;
struct fileno;
struct cqueue;


struct event {
	int fd;
	short events;
	double timeout;

	_Bool pending;

	int index; /* on .thread->L stack */

	struct thread *thread;
	TAILQ_ENTRY(event) tqe;

	struct fileno *fileno;
	LIST_ENTRY(event) fle;

	struct wakecb *wakecb;
}; /* struct event */


struct fileno {
	int fd;
	short state;

	LIST_HEAD(, event) events;

	LLRB_ENTRY(fileno) rbe;

	LIST_ENTRY(fileno) le;
}; /* struct fileno */


struct timer {
	double timeout;

	LLRB_ENTRY(timer) rbe;
}; /* struct timer */


struct thread {
	lua_State *L; /* only for coroutines */

	TAILQ_HEAD(, event) events;
	unsigned count;

	struct threads *threads;
	LIST_ENTRY(thread) le;

	double mintimeout;

	struct timer timer;
}; /* struct thread */

#define timer2thread(timer) ((struct thread *)((char *)(timer) - offsetof(struct thread, timer)))


struct cqueue {
	struct kpoll kp;

	struct {
		LLRB_HEAD(table, fileno) table;
		LIST_HEAD(, fileno) polling, outstanding, inactive;
	} fileno;

	struct {
		struct pool wakecb, fileno, event;
	} pool;

	struct {
		LIST_HEAD(threads, thread) polling, pending;
		struct thread *current;
		unsigned count;
	} thread;

	LLRB_HEAD(timers, timer) timers;

	struct cstack *cstack;

	LIST_ENTRY(cqueue) le;
}; /* struct cqueue */


static inline int fileno_cmp(const struct fileno *const a, const struct fileno *const b) {
	return a->fd - b->fd;
} /* fileno_cmp() */

LLRB_GENERATE_STATIC(table, fileno, rbe, fileno_cmp)


static inline int timer_cmp(const struct timer *const a, const struct timer *const b) {
	return (a->timeout < b->timeout)? -1 : (a->timeout > b->timeout)? 1 : (a < b)? -1 : (a > b)? 1 : 0;
} /* timer_cmp() */

LLRB_GENERATE_STATIC(timers, timer, rbe, timer_cmp)


struct stackinfo {
	struct cqueue *Q; /* actual cqueue object */
	lua_State *L; /* stack holding cqueue object reference (i.e. thread calling :step) */
	int self; /* stack index in L of cqueue object */
	lua_State *T; /* running thread */
	struct stackinfo *running; /* next running cqueue object in call stack */
}; /* struct stackinfo */

static void cstack_push(struct cstack *, struct stackinfo *);
static void cstack_pop(struct cstack *);
static _Bool cstack_isrunning(const struct cstack *, const struct cqueue *);

#define CALLINFO_INITIALIZER { 0, { 0, 0, 0, 0, -1 } }

struct callinfo {
	cqs_index_t self; /* stack index of cqueue object */

	struct {
		cqs_index_t value;
		int code;
		cqs_index_t thread;
		cqs_index_t object;
		int fd;
	} error;
}; /* struct callinfo */


static struct cqueue *cqueue_checkvalid(lua_State *L, int index, struct cqueue *Q) {
	luaL_argcheck(L, !!Q->cstack, index, "cqueue closed");
	return Q;
} /* cqueue_checkvalid() */


static struct cqueue *cqueue_checkself(lua_State *L, int index) {
	return cqueue_checkvalid(L, index, cqs_checkudata(L, index, 1, CQUEUE_CLASS));
} /* cqueue_checkself() */


static struct cqueue *cqueue_enter_nothrow(lua_State *L, struct callinfo *I, int index, struct cqueue *Q) {
	I->self = lua_absindex(L, index);

	I->error.value = 0;
	I->error.code = 0;
	I->error.thread = 0;
	I->error.object = 0;
	I->error.fd = -1;

	return Q;
} /* cqueue_enter_nothrow() */


static struct cqueue *cqueue_enter(lua_State *L, struct callinfo *I, int index) {
	return cqueue_enter_nothrow(L, I, index, cqueue_checkself(L, index));
} /* cqueue_enter() */


static cqs_error_t cqueue_tryalert(struct cqueue *Q) {
	if (!cstack_isrunning(Q->cstack, Q) || LIST_EMPTY(&Q->thread.pending)) {
		return kpoll_alert(&Q->kp);
	} else {
		return 0;
	}
} /* cqueue_tryalert() */

static void err_setvfstring(lua_State *L, struct callinfo *I, const char *fmt, va_list ap) {
	lua_pushvfstring(L, fmt, ap);
	I->error.value = lua_gettop(L);
} /* err_setvfstring() */

static void err_setfstring(lua_State *L, struct callinfo *I, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	err_setvfstring(L, I, fmt, ap);
	va_end(ap);
} /* err_setfstring() */

static void err_setcode(lua_State *L, struct callinfo *I, int code) {
	I->error.code = code;

	if (!I->error.value)
		err_setfstring(L, I, "%s", cqs_strerror(code));
} /* err_setcode() */

static void err_setthread(lua_State *L, struct callinfo *I, struct thread *T) {
	lua_pushthread(T->L);
	lua_xmove(T->L, L, 1);
	I->error.thread = lua_gettop(L);
} /* err_setthread() */

static void err_setobject(lua_State *L, struct callinfo *I, cqs_index_t index) {
	if (index)
		I->error.object = lua_absindex(L, index);
} /* err_setobject() */

static void err_setfd(lua_State *L NOTUSED, struct callinfo *I, int fd) {
	I->error.fd = fd;
} /* err_setfd() */

static void err_setinfo(lua_State *L, struct callinfo *I, int code, struct thread *T, int object, const char *fmt, ...) {
	/* set object first in case it's a relative index */
	if (object)
		err_setobject(L, I, object);

	if (T)
		err_setthread(L, I, T);

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		err_setvfstring(L, I, fmt, ap);
		va_end(ap);
	}

	/*
	 * set code after we set any string so we don't unnecessarily
	 * instantiate a string description
	 */
	if (code)
		err_setcode(L, I, code);
} /* err_setinfo() */

static _Bool err_onstack(lua_State *L NOTUSED, struct callinfo *I) {
	return I->error.value || I->error.thread || I->error.object;
} /* err_onstack() */

static void err_corrupt(lua_State *L, int index, const char *type) {
	luaL_error(L, "corrupt error stack: expected %s, got %s at index %d", type, luaL_typename(L, index), index);
} /* err_corrupt() */

static void err_checktype(lua_State *L, int index, int type) {
	if (lua_type(L, index) != type)
		err_corrupt(L, index, lua_typename(L, type));
} /* err_checktype() */

static const char *err_pushvalue(lua_State *L, struct callinfo *I) {
	if (I->error.value) {
		lua_pushvalue(L, I->error.value);
	} else {
		lua_pushstring(L, "no error message");
	}

	return lua_tostring(L, -1);
} /* err_pushvalue() */

static cqs_nargs_t err_pushinfo(lua_State *L, struct callinfo *I) {
	int nargs = 0;

	luaL_checkstack(L, 5, "too many arguments");

	err_pushvalue(L, I);
	nargs = 1;

	if (I->error.code) {
		lua_pushinteger(L, I->error.code);
		nargs = 2;
	}

	if (I->error.thread) {
		lua_settop(L, lua_gettop(L) + (2 - nargs));
		err_checktype(L, I->error.thread, LUA_TTHREAD);
		lua_pushvalue(L, I->error.thread);
		nargs = 3;
	}

	if (I->error.object) {
		lua_settop(L, lua_gettop(L) + (3 - nargs));
		if (lua_isnone(L, I->error.object))
			err_corrupt(L, I->error.object, "any");
		lua_pushvalue(L, I->error.object);
		nargs = 4;
	}

	if (I->error.fd != -1) {
		lua_settop(L, lua_gettop(L) + (4 - nargs));
		lua_pushinteger(L, I->error.fd);
		nargs = 5;
	}

	return nargs;
} /* err_pushinfo() */

static void err_error(lua_State *L, struct callinfo *I) {
	err_pushvalue(L, I);
	lua_error(L);
} /* err_error() */


static void cqueue_preinit(struct cqueue *Q) {
	memset(Q, 0, sizeof *Q);

	kpoll_preinit(&Q->kp);

	Q->thread.current = NULL;

	pool_init(&Q->pool.wakecb, sizeof (struct wakecb));
	pool_init(&Q->pool.fileno, sizeof (struct fileno));
	pool_init(&Q->pool.event, sizeof (struct event));
} /* cqueue_preinit() */


static void cstack_add(lua_State *, struct cqueue *);

static int cqueue_init(lua_State *L, struct cqueue *Q, int index) {
	int error;

	index = lua_absindex(L, index);

	if ((error = kpoll_init(&Q->kp)))
		return error;

	/*
	 * give ourselves an empty table of threads
	 */
	lua_newtable(L);
	cqs_setuservalue(L, index);

	/*
	 * associate ourselves with global continuation stack
	 */
	cstack_add(L, Q);

	return 0;
} /* cqueue_init() */


static void thread_del(lua_State *, struct cqueue *, struct callinfo *, struct thread *);
static int fileno_del(struct cqueue *, struct fileno *, _Bool);
static void cstack_del(struct cqueue *);
static int cstack_onclosefd(int *, void *);

/*
 * NOTE: Q->cstack can be NULL if cqueue_init() OOM'd. See cstack_closefd()
 * and cstack_del().
 */
static void cqueue_destroy(lua_State *L, struct cqueue *Q, struct callinfo *I) {
	struct cstack *cstack = Q->cstack;
	struct thread *thread;
	struct fileno *fileno;
	void *next;

	cstack_del(Q);

	Q->thread.current = NULL;

	while ((thread = LIST_FIRST(&Q->thread.pending))) {
		thread_del(L, Q, I, thread);
	}

	while ((thread = LIST_FIRST(&Q->thread.polling))) {
		thread_del(L, Q, I, thread);
	}

	for (fileno = LLRB_MIN(table, &Q->fileno.table); fileno; fileno = next) {
		next = LLRB_NEXT(table, &Q->fileno.table, fileno);
		fileno_del(Q, fileno, 0);
	}

	kpoll_destroy(&Q->kp, &cstack_onclosefd, cstack);

	pool_destroy(&Q->pool.event);
	pool_destroy(&Q->pool.fileno);
	pool_destroy(&Q->pool.wakecb);
} /* cqueue_destroy() */


static int cqueue_create(lua_State *L) {
	struct cqueue *Q;
	int error;

	Q = lua_newuserdata(L, sizeof *Q);

	cqueue_preinit(Q);

	luaL_getmetatable(L, CQUEUE_CLASS);
	lua_setmetatable(L, -2);

	if ((error = cqueue_init(L, Q, -1)))
		goto error;

	return 1;

error:
	lua_pushnil(L);
	lua_pushstring(L, cqs_strerror(error));
	lua_pushinteger(L, error);

	return 3;
} /* cqueue_new() */


static int cqueue_close(lua_State *L) {
	struct cqueue *Q = cqs_checkudata(L, 1, 1, CQUEUE_CLASS);
	struct callinfo I;

	/* disallow :close when invoked from a thread resumed by cqueue_step */
	luaL_argcheck(L, !Q->cstack || !cstack_isrunning(Q->cstack, Q), 1, "cqueue running");

	cqueue_enter_nothrow(L, &I, 1, Q);
	cqueue_destroy(L, Q, &I);

	return 0;
} /* cqueue_close() */


static int cqueue__gc(lua_State *L) {
	struct cqueue *Q = cqs_checkudata(L, 1, 1, CQUEUE_CLASS);
	struct callinfo I;

	cqueue_enter_nothrow(L, &I, 1, Q);
	cqueue_destroy(L, Q, &I);

	return 0;
} /* cqueue__gc() */


static void thread_move(struct thread *T, struct threads *list) {
	if (T->threads != list) {
		LIST_REMOVE(T, le);
		LIST_INSERT_HEAD(list, T, le);
		T->threads = list;
	}
} /* thread_move() */


static struct fileno *fileno_find(struct cqueue *Q, int fd) {
	struct fileno key;

	key.fd = fd;

	return LLRB_FIND(table, &Q->fileno.table, &key);
} /* fileno_find() */


static struct fileno *fileno_get(struct cqueue *Q, int fd, int *error) {
	struct fileno *fileno;

	if (!(fileno = fileno_find(Q, fd))) {
		if (!(fileno = pool_get(&Q->pool.fileno, error)))
			return NULL;

		fileno->fd = fd;
		fileno->state = 0;
		LIST_INIT(&fileno->events);

		LIST_INSERT_HEAD(&Q->fileno.inactive, fileno, le);
		LLRB_INSERT(table, &Q->fileno.table, fileno);
	}

	return fileno;
} /* fileno_get() */


static cqs_error_t fileno_signal(struct cqueue *Q, struct fileno *fileno, short events) {
	struct event *event;
	int error = 0, _error;

	LIST_FOREACH(event, &fileno->events, fle) {
		/* XXX: If POLLPRI should we always mark as pending? */
		if (event->events & events)
			event->pending = 1;

		thread_move(event->thread, &Q->thread.pending);

		if ((_error = cqueue_tryalert(Q)))
			error = _error;
	}

	return error;
} /* fileno_signal() */


static int fileno_ctl(struct cqueue *Q, struct fileno *fileno, short events) {
	int error;

	if ((error = kpoll_ctl(&Q->kp, fileno->fd, &fileno->state, events, fileno)))
		return error; /* XXX: Should we call fileno_signal? */

	LIST_REMOVE(fileno, le);

	if (fileno->state)
		LIST_INSERT_HEAD(&Q->fileno.polling, fileno, le);
	else
		LIST_INSERT_HEAD(&Q->fileno.inactive, fileno, le);

	return 0;
} /* fileno_ctl() */


static int fileno_update(struct cqueue *Q, struct fileno *fileno) {
	struct event *event;
	short events = 0;

	LIST_FOREACH(event, &fileno->events, fle) {
		events |= event->events;
	}

	return fileno_ctl(Q, fileno, events);
} /* fileno_update() */


static int fileno_del(struct cqueue *Q, struct fileno *fileno, _Bool update) {
	struct event *event;
	int error = 0;

	while ((event = LIST_FIRST(&fileno->events))) {
		event->fileno = NULL;
		LIST_REMOVE(event, fle);
	}

	if (update)
		error = fileno_update(Q, fileno);

	LLRB_REMOVE(table, &Q->fileno.table, fileno);

	LIST_REMOVE(fileno, le);

	pool_put(&Q->pool.fileno, fileno);

	return error;
} /* fileno_del() */


static cqs_error_t wakecb_wakeup(struct wakecb *cb) {
	struct cqueue *Q = cb->arg[0];
	struct event *event = cb->arg[1];

	event->pending = 1;
	thread_move(event->thread, &Q->thread.pending);

	return cqueue_tryalert(Q);
} /* wakecb_wakeup() */


#define object_pcall(L, I, T, index, field, ...) object_pcall((L), (I), (T), (index), (field), ((int[]){ __VA_ARGS__ }), countof(((int[]){ __VA_ARGS__ })))

NONNULL(1, 2, 5)
static cqs_status_t (object_pcall)(lua_State *L, struct callinfo *I, struct thread *T, int index, const char *field, int rtype[], int n) {
	int type, i, status;

	index = lua_absindex(L, index);
	lua_getfield(L, index, field);

	if (lua_isfunction(L, -1)) {
		lua_pushvalue(L, index);

		if (LUA_OK != (status = lua_pcall(L, 1, 1, 0))) {
			err_setinfo(L, I, 0, T, index, "error calling method %s: %s", field, lua_tostring(L, -1));

			return status;
		}
	}

	type = lua_type(L, -1);

	for (i = 0; i < n; i++) {
		if (type == rtype[i])
			return LUA_OK;
	}

	err_setinfo(L, I, 0, T, index, "error loading field %s: %s expected, got %s", field, lua_typename(L, rtype[0]), luaL_typename(L, -1));

	return LUA_ERRRUN;
} /* object_pcall() */


NONNULL(1, 2, 3, 6)
static int object_getcv(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T, int index, struct event *event) {
	struct condition *cv = lua_touserdata(L, index);
	int error;

	if (!(event->wakecb = pool_get(&Q->pool.wakecb, &error))) {
		err_setinfo(L, I, error, T, index, "unable to wait on conditional variable: %s", cqs_strerror(error));

		return LUA_ERRRUN;
	}

	wakecb_init(event->wakecb, &wakecb_wakeup, Q, event);
	wakecb_add(event->wakecb, cv);

	return LUA_OK;
} /* object_getcv() */


NONNULL(1, 2, 3, 6)
static cqs_status_t object_getinfo(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T, int index, struct event *event) {
	int status;

	/* optimize simple timeout */
	if (lua_isnumber(T->L, index)) {
		event->timeout = abstimeout(lua_tonumber(T->L, index));

		return LUA_OK;
	}

	/*
	 * push onto our local stack so we don't dirty the thread stack and
	 * also to allow fast upvalue comparisons
	 */
	lua_pushvalue(T->L, index);
	lua_xmove(T->L, L, 1);

	if (cqs_testudata(L, -1, 2)) {
		event->fd = cqs_socket_pollfd(L, -1);
		event->events = cqs_socket_events(L, -1);
		event->timeout = abstimeout(cqs_socket_timeout(L, -1));
	} else if (cqs_testudata(L, -1, 3)) {
		if ((LUA_OK != (status = object_getcv(L, Q, I, T, -1, event))))
			goto oops;
	} else {
		if (LUA_OK != (status = object_pcall(L, I, T, -1, "pollfd", LUA_TNUMBER, LUA_TUSERDATA, LUA_TNIL)))
			goto oops;

		if (lua_isuserdata(L, -1) && cqs_testudata(L, -1, 3)) {
			if ((LUA_OK != (status = object_getcv(L, Q, I, T, -1, event))))
				goto oops;
		} else {
			event->fd = luaL_optinteger(L, -1, -1);
			event->fd = MAX(event->fd, -1);
		}

		lua_pop(L, 1); /* pop fd or condvar */

		if (LUA_OK != (status = object_pcall(L, I, T, -1, "events", LUA_TNUMBER, LUA_TSTRING, LUA_TNIL)))
			goto oops;

		if (lua_isnumber(L, -1)) {
			event->events = (POLLIN|POLLOUT|POLLPRI) & lua_tointeger(L, -1);
		} else {
			const char *mode = luaL_optstring(L, -1, "");

			event->events = 0;

			while (*mode) {
				if (*mode == 'r')
					event->events |= POLLIN;
				else if (*mode == 'w')
					event->events |= POLLOUT;
				else if (*mode == 'p')
					event->events |= POLLPRI;
				mode++;
			}
		}

		lua_pop(L, 1); /* pop event mode */

		if (LUA_OK != (status = object_pcall(L, I, T, -1, "timeout", LUA_TNUMBER, LUA_TNIL)))
			goto oops;

		event->timeout = abstimeout(luaL_optnumber(L, -1, event->timeout));

		lua_pop(L, 1); /* pop timeout */
	}

	lua_pop(L, 1); /* pop object */

	return LUA_OK;
oops:
	return status;
} /* object_getinfo() */


static void event_init(struct event *event, struct thread *T, int index) {
	memset(event, 0, sizeof *event);

	event->fd = -1;
	event->timeout = NAN;
	event->index = index;
	event->thread = T;

	TAILQ_INSERT_TAIL(&T->events, event, tqe);
	T->count++;
} /* event_init() */


static cqs_status_t event_add(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T, int index) {
	struct event *event;
	struct fileno *fileno;
	int error, status;

	if (!(event = pool_get(&Q->pool.event, &error)))
		goto error;

	event_init(event, T, index);

	if (LUA_OK != (status = object_getinfo(L, Q, I, T, index, event)))
		return status;

	if (event->fd >= 0 && event->events) {
		if (!(fileno = fileno_get(Q, event->fd, &error)))
			goto error;

		LIST_INSERT_HEAD(&fileno->events, event, fle);
		event->fileno = fileno;

		LIST_REMOVE(fileno, le);
		LIST_INSERT_HEAD(&Q->fileno.outstanding, fileno, le);
	}

	return LUA_OK;
error:
	err_setinfo(L, I, error, T, index, "unable to add event: %s", cqs_strerror(error));

	return LUA_ERRRUN;
} /* event_add() */


static void event_del(struct cqueue *Q, struct event *event) {
	if (event->wakecb) {
		wakecb_del(event->wakecb);
		pool_put(&Q->pool.wakecb, event->wakecb);
	}

	if (event->fileno) {
		LIST_REMOVE(event->fileno, le);
		LIST_INSERT_HEAD(&Q->fileno.outstanding, event->fileno, le);

		LIST_REMOVE(event, fle);
	}

	TAILQ_REMOVE(&event->thread->events, event, tqe);
	assert(event->thread->count > 0);
	event->thread->count--;

	pool_put(&Q->pool.event, event);
} /* event_del() */


static void timer_init(struct timer *timer) {
	timer->timeout = NAN;
} /* timer_init() */


static void timer_del(struct cqueue *Q, struct timer *timer) {
	if (isfinite(timer->timeout)) {
		LLRB_REMOVE(timers, &Q->timers, timer);
		timer->timeout = NAN;
	}
} /* timer_del() */


static void timer_add(struct cqueue *Q, struct timer *timer, double timeout) {
	timer_del(Q, timer);

	if (isfinite(timeout)) {
		timer->timeout = timeout;
		LLRB_INSERT(timers, &Q->timers, timer);
	}
} /* timer_add() */


static void timer_destroy(struct cqueue *Q, struct timer *timer) {
	timer_del(Q, timer);
} /* timer_destroy() */


static double thread_timeout(struct thread *T) {
	double timeout = NAN;
	struct event *event;

	TAILQ_FOREACH(event, &T->events, tqe) {
		timeout = mintimeout(timeout, event->timeout);
	}

	return timeout;
} /* thread_timeout() */


static void thread_add(lua_State *L, struct cqueue *Q, struct callinfo *I, int index) {
	struct thread *T;

	index = lua_absindex(L, index);

	T = lua_newuserdata(L, sizeof *T);
	memset(T, 0, sizeof *T);
	TAILQ_INIT(&T->events);
	timer_init(&T->timer);

	/* anchor new lua_State to our thread context */
	lua_pushvalue(L, index);
	cqs_setuservalue(L, -2);
	T->L = lua_tothread(L, index);

	/* anchor thread context to cqueue object */
	cqs_getuservalue(L, I->self);
	lua_pushvalue(L, -2);
	lua_rawsetp(L, -2, CQS_UNIQUE_LIGHTUSERDATA_MASK(T));
	lua_pop(L, 2);

	LIST_INSERT_HEAD(&Q->thread.pending, T, le);
	T->threads = &Q->thread.pending;
	Q->thread.count++;
} /* thread_add() */


static void thread_del(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T) {
	struct event *event;

	while ((event = TAILQ_FIRST(&T->events))) {
		event_del(Q, event);
	}
	timer_destroy(Q, &T->timer);
	LIST_REMOVE(T, le);
	Q->thread.count--;

	/*
	 * XXX: These lua operations are documented as able to longjmp on
	 * OOM. However, inspection of the lua source suggests that when used
	 * as below they won't throw.
	 *   - In lua5.1 pushing a lightuserdata doesn't allocate (they're
	 *     stack allocated)
	 *   - rawset doesn't allocate if the key already exists in the table
	 *     (which it always does for this function)
	 */
	cqs_getuservalue(L, I->self);

	/* set thread's uservalue (it's thread) to nil */
	lua_rawgetp(L, -1, CQS_UNIQUE_LIGHTUSERDATA_MASK(T));
	lua_pushnil(L);
	cqs_setuservalue(L, -2);
	lua_pop(L, 1);
	T->L = NULL;

	/* remove thread from cqueues's thread table */
	lua_pushnil(L);
	lua_rawsetp(L, -2, CQS_UNIQUE_LIGHTUSERDATA_MASK(T));
	lua_pop(L, 1);
} /* thread_del() */


static cqs_status_t cqueue_update(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T) {
	struct fileno *fileno, *next;
	struct event *event;
	int error;

	for (fileno = LIST_FIRST(&Q->fileno.outstanding); fileno; fileno = next) {
		next = LIST_NEXT(fileno, le);

		if ((error = fileno_update(Q, fileno)))
			goto error;
	}

	return LUA_OK;
error:
	LIST_FOREACH(event, &fileno->events, fle) {
		if (event->thread != T)
			continue;

		lua_pushvalue(T->L, event->index);
		lua_xmove(T->L, L, 1);
		err_setobject(L, I, lua_gettop(L));

		break;
	}

	err_setfd(L, I, fileno->fd);
	err_setinfo(L, I, error, T, 0, "unable to update event disposition: %s (fd:%d)", cqs_strerror(error), fileno->fd);

	return LUA_ERRRUN;
} /* cqueue_update() */


static cqs_error_t cqueue_reboot(struct cqueue *Q, _Bool stop, _Bool restart) {
	if (stop) {
		struct fileno *fileno;
		struct thread *thread;

		while ((fileno = LIST_FIRST(&Q->fileno.polling))) {
			LIST_REMOVE(fileno, le);
			LIST_INSERT_HEAD(&Q->fileno.outstanding, fileno, le);
		}

		LIST_FOREACH(fileno, &Q->fileno.outstanding, le) {
			fileno->state = 0;
		}

		while ((thread = LIST_FIRST(&Q->thread.polling))) {
			thread_move(thread, &Q->thread.pending);
		}

		kpoll_destroy(&Q->kp, &cstack_onclosefd, Q->cstack);
	}

	if (restart) {
		int error;

		if ((error = kpoll_init(&Q->kp)))
			return error;
	}

	return 0;
} /* cqueue_reboot() */


static _Bool auxL_xcopy(lua_State *from, lua_State *to, int count) {
	int index;

	if (!lua_checkstack(from, count)
	||  !lua_checkstack(to, count + LUA_MINSTACK))
		return 0;

	for (index = 1; index <= count; index++)
		lua_pushvalue(from, index);

	lua_xmove(from, to, count);

	return 1;
} /*  auxL_xcopy() */


static cqs_status_t cqueue_resume(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T) {
	int otop = lua_gettop(L), nargs, nres, status, tmp_status, index;
	struct event *event;

	status = lua_status(T->L);
	if (status == LUA_YIELD && lua_islightuserdata(T->L, 1) && lua_topointer(T->L, 1) == CQUEUE__POLL) {
		/*
		 * Preserve any previously yielded objects on another stack
		 * until we can call cqueue_update() because when
		 * lua_resume() returns the thread stack will only contain
		 * new objects. Pausing the GC isn't a viable option because
		 * we don't know if or when lua_resume() will return.
		 */
		if (!auxL_xcopy(T->L, L, lua_gettop(T->L)))
			goto nospace;

		nargs = 0;

		if (!lua_checkstack(T->L, T->count + LUA_MINSTACK))
			goto nospace;

		while ((event = TAILQ_FIRST(&T->events))) {
			if (event->pending) {
				lua_pushvalue(T->L, event->index);
				nargs++;
			}

			event_del(Q, event);
		}
	} else {
		nargs = lua_gettop(T->L);
		if (status != LUA_YIELD) {
			if (nargs > 0)
				nargs -= 1; /* exclude function */
		}
	}

	timer_del(Q, &T->timer);

	cstack_push(Q->cstack, &(struct stackinfo){ Q, L, I->self, T->L });

#if LUA_VERSION_NUM < 504
	status = lua_resume(T->L, L, nargs);
	nres = lua_gettop(T->L);
#else
	status = lua_resume(T->L, L, nargs, &nres);
#endif

	cstack_pop(Q->cstack);

	switch (status) {
	case LUA_YIELD:
		if (nres > 0 && lua_islightuserdata(T->L, 1) && lua_topointer(T->L, 1) == CQUEUE__POLL) {
			for (index = 2; index <= nres; index++) {
				switch (lua_type(T->L, index)) {
				case LUA_TNIL:
					continue;
				default:
					if (LUA_OK != (status = event_add(L, Q, I, T, index)))
						goto defunct;
				}
			}

			if (LUA_OK != (status = cqueue_update(L, Q, I, T)))
				goto defunct;

			timer_add(Q, &T->timer, thread_timeout(T));

			if (!TAILQ_EMPTY(&T->events) || isfinite(T->timer.timeout))
				thread_move(T, &Q->thread.polling);
		} else {
			if (LUA_OK != (tmp_status = cqueue_update(L, Q, I, T))) {
				status = tmp_status;
				goto defunct;
			}

			break;
		}
		break;
	case LUA_OK:
		if (LUA_OK != (status = cqueue_update(L, Q, I, T)))
			goto defunct;

		thread_del(L, Q, I, T);

		break;
	default:
		if (LUA_OK != cqueue_update(L, Q, I, T))
			goto defunct;

		lua_xmove(T->L, L, 1); /* move error message */
		I->error.value = lua_gettop(L);
		err_setthread(L, I, T);
defunct:
		thread_del(L, Q, I, T);

		break;
	} /* switch() */

	/* discard objects preserved while resuming coroutine */
	if (!err_onstack(L, I))
		lua_settop(L, otop);

	return status;
nospace:
	err_setinfo(L, I, 0, T, 0, "stack overflow");
	status = LUA_ERRMEM;

	goto defunct;
} /* cqueue_resume() */


static cqs_status_t cqueue_process_threads(lua_State *L, struct cqueue *Q, struct callinfo *I) {
	cqs_status_t status;
	struct thread *nxt;

	for (; Q->thread.current; Q->thread.current = nxt) {
		nxt = LIST_NEXT(Q->thread.current, le);

		if (LUA_OK != (status = cqueue_resume(L, Q, I, Q->thread.current))) {
			return status;
		}
	}

	return LUA_OK;
} /* cqueue_process_threads() */


static cqs_status_t cqueue_process(lua_State *L, struct cqueue *Q, struct callinfo *I) {
	int onalert = 0;
	kpoll_event_t *ke;
	struct fileno *fileno;
	struct event *event;
	struct thread *T;
	struct timer *timer;
	double curtime;
	short events;
	int status;

	KPOLL_FOREACH(ke, &Q->kp) {
		if (kpoll_isalert(&Q->kp, ke)) {
			onalert = 1;

			continue;
		}

		fileno = kpoll_udata(ke);
		events = kpoll_pending(ke);

		fileno_signal(Q, fileno, events);
		fileno->state = kpoll_diff(ke, fileno->state);
	}

	curtime = monotime();

	LLRB_FOREACH(timer, timers, &Q->timers) {
		if (isgreater(timer->timeout, curtime))
			break;

		T = timer2thread(timer);

		TAILQ_FOREACH(event, &T->events, tqe) {
			if (islessequal(event->timeout, curtime))
				event->pending = 1;
		}

		thread_move(T, &Q->thread.pending);
	}

	assert(NULL == Q->thread.current);
	Q->thread.current = LIST_FIRST(&Q->thread.pending);
	if (LUA_OK != (status = cqueue_process_threads(L, Q, I))) {
		return status;
	}

	if (onalert) {
		kpoll_calm(&Q->kp);
	}

	return LUA_OK;
} /* cqueue_process() */


static double cqueue_timeout_(struct cqueue *Q) {
	struct timer *timer;
	double curtime;

	if (!(timer = LLRB_MIN(timers, &Q->timers)))
		return NAN;

	curtime = monotime();

	return (islessequal(timer->timeout, curtime))? 0.0 : timer->timeout - curtime;
} /* cqueue_timeout_() */


#if LUA_VERSION_NUM >= 502
LUA_KFUNCTION(cqueue_step_cont) {
#else
static int cqueue_step_cont(lua_State *L) {
#endif
	int nargs = lua_gettop(L);
	struct callinfo I = CALLINFO_INITIALIZER;
	struct cqueue *Q = cqueue_checkself(L, 1);
	struct thread *T = Q->thread.current;
	if (!T) {
		luaL_error(L, "cqueue not yielded");
		NOTREACHED;
	}
	if (lua_islightuserdata(L, 2) && lua_touserdata(L, 2) == CQUEUE__POLL) {
		luaL_error(L, "cannot resume a coroutine passing internal cqueues._POLL value as first parameter");
		NOTREACHED;
	}
	/* move arguments onto resumed stack */
	lua_xmove(L, T->L, nargs-1);

	cqueue_enter(L, &I, 1);

	switch(cqueue_process_threads(L, Q, &I)) {
	case LUA_OK:
		break;
	case LUA_YIELD:
		/* clear everything off the stack except for cqueue object; `I` now invalid */
		lua_settop(L, 1);
#if LUA_VERSION_NUM >= 502
		/* move arguments onto 'main' stack to return them from this yield */
		nargs = lua_gettop(Q->thread.current->L);
		lua_xmove(Q->thread.current->L, L, nargs);
		return lua_yieldk(L, nargs, 0, cqueue_step_cont);
#else
		lua_pushliteral(L, "yielded");
		/* move arguments onto 'main' stack to return them from this yield */
		nargs = lua_gettop(Q->thread.current->L);
		lua_xmove(Q->thread.current->L, L, nargs);
		return nargs+1;
#endif
	default:
		goto oops;
	}

	lua_pushboolean(L, 1);

	return 1;
oops:
	Q->thread.current = NULL;
	lua_pushboolean(L, 0);
	return 1 + err_pushinfo(L, &I);
} /* yield_cont() */


static int cqueue_step(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;
	double timeout;
	int error;
	int nargs;

	lua_settop(L, 2);

	Q = cqueue_enter(L, &I, 1);

	if (Q->thread.current) {
		return luaL_error(L, "cannot step live cqueue");
	}

	if (Q->thread.count && LIST_EMPTY(&Q->thread.pending)) {
		timeout = mintimeout(luaL_optnumber(L, 2, NAN), cqueue_timeout_(Q));
	} else {
		timeout = 0.0;
	}

	if ((error = kpoll_wait(&Q->kp, timeout))) {
		err_setfstring(L, &I, "error polling: %s", cqs_strerror(error));
		err_setcode(L, &I, error);
		goto oops;
	}

	switch(cqueue_process(L, Q, &I)) {
	case LUA_OK:
		break;
	case LUA_YIELD:
		/* clear everything off the stack except for cqueue object; `I` now invalid */
		lua_settop(L, 1);
#if LUA_VERSION_NUM >= 502
		/* move arguments onto 'main' stack to return them from this yield */
		nargs = lua_gettop(Q->thread.current->L);
		lua_xmove(Q->thread.current->L, L, nargs);
		return lua_yieldk(L, nargs, 0, cqueue_step_cont);
#else
		lua_pushliteral(L, "yielded");
		/* move arguments onto 'main' stack to return them from this yield */
		nargs = lua_gettop(Q->thread.current->L);
		lua_xmove(Q->thread.current->L, L, nargs);
		return nargs+1;
#endif
	default:
		goto oops;
	}

	lua_pushboolean(L, 1);

	return 1;
oops:
	Q->thread.current = NULL;
	lua_pushboolean(L, 0);
	return 1 + err_pushinfo(L, &I);
} /* cqueue_step() */


static int cqueue_attach(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;
	int error;

	lua_settop(L, 2);

	Q = cqueue_enter(L, &I, 1);
	luaL_checktype(L, 2, LUA_TTHREAD);

	thread_add(L, Q, &I, 2);

	if ((error = cqueue_tryalert(Q)))
		goto error;

	lua_pushvalue(L, 1); /* return self */

	return 1;
error:
	lua_pushnil(L);
	lua_pushstring(L, cqs_strerror(error));
	lua_pushinteger(L, error);

	return 3;
} /* cqueue_attach() */


static int cqueue_wrap(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;
	struct lua_State *newL;
	int top, error;

	top = lua_gettop(L);

	Q = cqueue_enter(L, &I, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);

	newL = lua_newthread(L);
	lua_insert(L, 2);
	luaL_checkstack(newL, top - 1, "too many arguments");
	lua_xmove(L, newL, top - 1);

	thread_add(L, Q, &I, -1);

	if ((error = cqueue_tryalert(Q)))
		goto error;

	lua_pushvalue(L, 1); /* return self */

	return 1;
error:
	lua_pushnil(L);
	lua_pushstring(L, cqs_strerror(error));
	lua_pushinteger(L, error);

	return 3;
} /* cqueue_wrap() */


static int cqueue_alert(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);
	int error;

	if ((error = kpoll_alert(&Q->kp)))
		goto error;

	lua_pushvalue(L, 1);

	return 1;
error:
	lua_pushnil(L);
	lua_pushstring(L, cqs_strerror(error));
	lua_pushinteger(L, error);

	return 3;
} /* cqueue_alert() */


static int cqueue_empty(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);

	lua_pushboolean(L, !Q->thread.count);

	return 1;
} /* cqueue_empty() */


static int cqueue_count(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);

	lua_pushinteger(L, Q->thread.count);

	return 1;
} /* cqueue_count() */


static cqs_error_t cqueue_cancelfd(struct cqueue *Q, int fd) {
	struct fileno *fileno;
	int error = 0, _error;

	if (!(fileno = fileno_find(Q, fd)))
		return 0;

	if ((_error = fileno_signal(Q, fileno, POLLIN|POLLOUT|POLLPRI)))
		error = _error;
	if ((_error = fileno_ctl(Q, fileno, 0)))
		error = _error;

	return error;
} /* cqueue_cancelfd() */


static int cqueue_checkfd(lua_State *L, struct callinfo *I, int index) {
	int fd;

	if (!lua_isnil(L, index) && !lua_isnumber(L, index)) {
		if (LUA_OK != object_pcall(L, I, NULL, index, "pollfd", LUA_TNUMBER))
			err_error(L, I);

		fd = luaL_optint(L, -1, -1);
		lua_pop(L, 1);
	} else {
		fd = luaL_optint(L, index, -1);
	}

	return fd;
} /* cqueue_checkfd() */


static int cqueue_cancel(lua_State *L) {
	struct callinfo I;
	int top = lua_gettop(L);
	struct cqueue *Q = cqueue_enter(L, &I, 1);
	int index;

	for (index = 2; index <= top; index++)
		cqueue_cancelfd(Q, cqueue_checkfd(L, &I, index));

	return 0;
} /* cqueue_cancel() */


static int cqueue_reset(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);
	int error;

	if ((error = cqueue_reboot(Q, 1, 1)))
		return luaL_error(L, "unable to reset continuation queue: %s", cqs_strerror(error));

	return 0;
} /* cqueue_reset() */


cqs_error_t cqs_sigmask(int how, const sigset_t *set, sigset_t *oset) {
	if (oset)
		sigemptyset(oset);

#if (defined _REENTRANT || defined _THREAD_SAFE) && _POSIX_THREADS > 0
	return pthread_sigmask(how, set, oset);
#else
	return sigprocmask(how, set, oset)? errno : 0;
#endif
} /* cqs_sigmask() */


/*
 * cqs_pselect
 *
 * kqueue-backed pselect for OpenBSD and Apple. Though Apple provides
 * pselect in libc, it's a broken wrapper around select which doesn't solve
 * the race condition.
 *
 * Logical steps:
 *
 * 1) check for signals which will be unmasked and deliverable on select;
 * 2) if any are pending, allow delivery and return EINTR; otherwise,
 * 3) setup kqueue listener before we unblock;
 * 4) execute select with specified signal mask.
 *
 * NOTES:
 * 	o EVFILT_SIGNAL is an edge-triggered filter, which means that if a
 * 	  signal is already pending when we add the listener, we won't be
 * 	  notified when it's subsequently delivered. The solution is just to
 * 	  check the pending set ahead of time.
 *
 * 	o This implementation doesn't try to minimize the signal disposition
 * 	  race where the application doesn't use the proper mask/unmask
 * 	  pattern. In particular, it calls sigpending earlier rather later.
 * 	  In the future it might even optimize by not installing a filter
 * 	  for signals already unblocked.
 */
static int cqs_pselect(int nfds, fd_set *_rfds, fd_set *wfds, fd_set *efds, const struct timespec *_timeout, const sigset_t *_mask, int *_error) {
#if __OpenBSD__ || __APPLE__ || (__NetBSD__ && __NetBSD_Version__ < 600000000)
	fd_set rfds;
	struct timeval *timeout;
	sigset_t omask, mask, pending;
	int kq = -1, error;
	struct kevent event[NSIG];
	unsigned nevent = 0;

	if (_rfds)
		FD_COPY(_rfds, &rfds);
	else
		FD_ZERO(&rfds);

	timeout = (_timeout)? &(struct timeval){ _timeout->tv_sec, _timeout->tv_nsec / 1000 } : NULL;

	if (_mask)
		mask = *_mask;
	else
		cqs_sigmask(SIG_SETMASK, NULL, &mask);

	sigpending(&pending);

	for (int i = 1; i < NSIG && nevent < countof(event); i++) {
		struct sigaction sa;

		if (i == SIGKILL || i == SIGSTOP)
			continue;

		if (sigismember(&mask, i))
			continue;

		if (0 != sigaction(i, NULL, &sa))
			goto syerr;

		if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN)
			continue;

		if (sigismember(&pending, i)) {
			/* allow signals to be delivered */
			if ((error = cqs_sigmask(SIG_SETMASK, &mask, &omask)))
				goto error;

			cqs_sigmask(SIG_SETMASK, &omask, NULL);

			error = EINTR;
			goto error;
		}

		EV_SET(&event[nevent], i, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
		nevent++;
	}

	if (nevent > 0) {
		if (-1 == (kq = kqueue()))
			goto syerr;

		if (0 != kevent(kq, event, nevent, 0, 0, 0))
			goto syerr;

		if (kq >= (int)FD_SETSIZE) {
			error = EINVAL;
			goto error;
		}

		FD_SET(kq, &rfds);
	}

	if ((error = cqs_sigmask(SIG_SETMASK, &mask, &omask)))
		goto error;

	if (-1 == (nfds = select(MAX(nfds, kq + 1), &rfds, wfds, efds, timeout)))
		*_error = errno;

	cqs_sigmask(SIG_SETMASK, &omask, NULL);

	if (nfds > 0 && kq != -1) {
		if (FD_ISSET(kq, &rfds) && !--nfds) {
			error = EINTR;
			goto error;
		}

		FD_CLR(kq, &rfds);

		if (_rfds)
			FD_COPY(&rfds, _rfds);
	}

	cqs_closefd(&kq);

	return nfds;
syerr:
	error = errno;
error:
	cqs_closefd(&kq);

	*_error = error;

	return -1;
#else
	if (-1 == (nfds = pselect(nfds, _rfds, wfds, efds, _timeout, _mask)))
		*_error = errno;

	return nfds;
#endif
} /* cqs_pselect() */


static int cqueue_pause(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);
	sigset_t block;
	fd_set rfds;
	int index, error;

	if ((error = cqs_sigmask(SIG_SETMASK, NULL, &block)))
		goto error;

	for (index = 2; index <= lua_gettop(L); index++) {
		sigdelset(&block, luaL_checkint(L, index));
	}

	/* FD_SETSIZE unsigned on FreeBSD. */
	if (Q->kp.fd < 0 || Q->kp.fd >= (int)FD_SETSIZE)
		return luaL_error(L, "cqueue:pause: fd %d outside allowable range 0..%d", Q->kp.fd, (int)(FD_SETSIZE - 1));

	FD_ZERO(&rfds);
	FD_SET(Q->kp.fd, &rfds);

	if (-1 == cqs_pselect(Q->kp.fd + 1, &rfds, NULL, NULL, f2ts(cqueue_timeout_(Q)), &block, &error)) {
		if (error != EINTR)
			goto error;
	}

	return 0;
error:
	return luaL_error(L, "cqueue:pause: %s", cqs_strerror(error));
} /* cqueue_pause() */


static int cqueue_pollfd(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);

	lua_pushinteger(L, Q->kp.fd);

	return 1;
} /* cqueue_pollfd() */


static int cqueue_events(lua_State *L) {
	cqueue_checkself(L, 1);

	lua_pushliteral(L, "r");

	return 1;
} /* cqueue_events() */


static int cqueue_timeout(lua_State *L) {
	struct cqueue *Q = cqueue_checkself(L, 1);

	if (!LIST_EMPTY(&Q->thread.pending)) {
		lua_pushnumber(L, 0.0);
	} else {
		double timeout = cqueue_timeout_(Q);

		if (isfinite(timeout))
			lua_pushnumber(L, timeout);
		else
			lua_pushnil(L);
	}

	return 1;
} /* cqueue_timeout() */


static int cqueue_type(lua_State *L) {
	struct cqueue *Q;

	if ((Q = cqs_testudata(L, 1, 1))) {
		if (Q->cstack) {
			lua_pushstring(L, "controller");
		} else {
			lua_pushstring(L, "closed controller");
		}
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* cqueue_type() */


static int cqueue_interpose(lua_State *L) {
	return cqs_interpose(L, CQUEUE_CLASS);
} /* cqueue_interpose() */


static int cqueue_monotime(lua_State *L) {
	lua_pushnumber(L, monotime());

	return 1;
} /* cqueue_monotime() */


/*
 * C O N T I N U A T I O N  S T A C K  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef CS /* defined by Solaris in /usr/include/sys/crtctl.h */

struct cstack {
	LIST_HEAD(, cqueue) cqueues;

	struct stackinfo *running;
}; /* struct cstack */


static struct cstack *cstack_self(lua_State *L) {
	static const int index = 47;
	struct cstack *CS;

	lua_rawgetp(L, LUA_REGISTRYINDEX, CQS_UNIQUE_LIGHTUSERDATA_MASK(&index));

	CS = lua_touserdata(L, -1);

	lua_pop(L, 1);

	if (CS)
		return CS;

	CS = lua_newuserdata(L, sizeof *CS);
	memset(CS, 0, sizeof *CS);

	LIST_INIT(&CS->cqueues);

	lua_rawsetp(L, LUA_REGISTRYINDEX, CQS_UNIQUE_LIGHTUSERDATA_MASK(&index));

	return CS;
} /* cstack_self() */


static void cstack_add(lua_State *L, struct cqueue *Q) {
	Q->cstack = cstack_self(L);
	LIST_INSERT_HEAD(&Q->cstack->cqueues, Q, le);
} /* cstack_add() */


static void cstack_del(struct cqueue *Q) {
	/* NB: Q->cstack can be NULL. See cqueue_destroy(). */
	if (Q->cstack) {
		LIST_REMOVE(Q, le);
		Q->cstack = NULL;
	}
} /* cstack_del() */


static void cstack_cancelfd(struct cstack *CS, int fd) {
	struct cqueue *Q;

	LIST_FOREACH(Q, &CS->cqueues, le) {
		cqueue_cancelfd(Q, fd);
	}
} /* cstack_cancelfd() */


static void cstack_closefd(struct cstack *CS, int *fd) {
	/* NB: CS can be NULL. See cqueue_destroy(). */
	if (CS) {
		cstack_cancelfd(CS, *fd);
	}

	cqs_closefd(fd);
} /* cstack_closefd() */


/* NB: libevent-style prototype similar to dns.c and socket.c close handlers */
static int cstack_onclosefd(int *fd, void *CS) {
	cstack_closefd(CS, fd);
	return 0;
} /* cstack_onclosefd() */


static int cstack_cancel(lua_State *L) {
	struct callinfo I = CALLINFO_INITIALIZER;
	struct cstack *CS = cstack_self(L);
	int index, fd;

	for (index = 1; index <= lua_gettop(L); index++) {
		fd = cqueue_checkfd(L, &I, index);
		cstack_cancelfd(CS, fd);
	}

	return 0;
} /* cstack_cancel() */


void cqs_cancelfd(lua_State *L, int fd) {
	cstack_cancelfd(cstack_self(L), fd);
} /* cqs_cancelfd() */


static int cstack_reset(lua_State *L) {
	struct cstack *CS = cstack_self(L);
	struct cqueue *Q;
	int error;

	LIST_FOREACH(Q, &CS->cqueues, le) {
		cqueue_reboot(Q, 1, 0);
	}

	LIST_FOREACH(Q, &CS->cqueues, le) {
		if ((error = cqueue_reboot(Q, 0, 1)))
			return luaL_error(L, "unable to reset continuation queue: %s", cqs_strerror(error));
	}

	return 0;
} /* cstack_reset() */


static void cstack_push(struct cstack *CS, struct stackinfo *info) {
	info->running = CS->running;
	CS->running = info;
} /* cstack_push() */


static void cstack_pop(struct cstack *CS) {
	CS->running = CS->running->running;
} /* cstack_push() */


static _Bool cstack_isrunning(const struct cstack *CS, const struct cqueue *Q) {
	struct stackinfo *info;

	for (info = CS->running; info; info = info->running) {
		if (info->Q == Q)
			return 1;
	}

	return 0;
} /* cstack_isrunning() */


static int cstack_running(lua_State *L) {
	struct cstack *CS = cstack_self(L);

	if (CS->running) {
		lua_pushvalue(CS->running->L, CS->running->self);
		lua_xmove(CS->running->L, L, 1);
		lua_pushboolean(L, CS->running->T == L);
	} else {
		lua_pushnil(L);
		lua_pushboolean(L, 0);
	}

	return 2;
} /* cstack_running() */


/*
 * C Q U E U E S  M O D U L E  L I N K A G E
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const luaL_Reg cqueue_methods[] = {
	{ "step",    &cqueue_step },
#if LUA_VERSION_NUM < 502
	{ "step_resume", &cqueue_step_cont },
#endif
	{ "attach",  &cqueue_attach },
	{ "wrap",    &cqueue_wrap },
	{ "alert",   &cqueue_alert },
	{ "empty",   &cqueue_empty },
	{ "count",   &cqueue_count },
	{ "cancel",  &cqueue_cancel },
	{ "reset",   &cqueue_reset },
	{ "pause",   &cqueue_pause },
	{ "pollfd",  &cqueue_pollfd },
	{ "events",  &cqueue_events },
	{ "timeout", &cqueue_timeout },
	{ "close",   &cqueue_close },
	{ NULL,      NULL }
}; /* cqueue_methods[] */


static const luaL_Reg cqueue_metatable[] = {
	{ "__gc", &cqueue__gc },
	{ NULL,   NULL }
}; /* cqueue_metatable[] */


static const luaL_Reg cqueues_globals[] = {
	{ "create",    &cqueue_create },
	{ "type",      &cqueue_type },
	{ "interpose", &cqueue_interpose },
	{ "monotime",  &cqueue_monotime },
	{ "cancel",    &cstack_cancel },
	{ "reset",     &cstack_reset },
	{ "running",   &cstack_running },
	{ NULL,        NULL }
}; /* cqueues_globals[] */


int luaopen__cqueues(lua_State *L) {
	/* initialize our dependencies used for fast metatable lookup */
	cqs_requiref(L, "_cqueues.socket", &luaopen__cqueues_socket, 0);
	cqs_requiref(L, "_cqueues.condition", &luaopen__cqueues_condition, 0);
	lua_pop(L, 2);

	/* push functions with shared upvalues for fast metatable lookup */
	cqs_pushnils(L, 3); /* initial upvalues */
	cqs_newmetatable(L, CQUEUE_CLASS, cqueue_methods, cqueue_metatable, 3);
	lua_pushvalue(L, -1); /* push self as replacement upvalue */
	cqs_setmetaupvalue(L, -2, 1); /* insert self as 1st upvalue */
	luaL_getmetatable(L, CQS_SOCKET);
	cqs_setmetaupvalue(L, -2, 2); /* insert socket as 2nd upvalue */
	luaL_getmetatable(L, CQS_CONDITION);
	cqs_setmetaupvalue(L, -2, 3); /* insert condition as 3rd upvalue */

	luaL_newlibtable(L, cqueues_globals);
	lua_pushvalue(L, -2); /* capture metatable as upvalue */
	luaL_getmetatable(L, CQS_SOCKET);
	luaL_getmetatable(L, CQS_CONDITION);
	luaL_setfuncs(L, cqueues_globals, 3);

	/* add magic value used to accomplish multilevel yielding */
	lua_pushlightuserdata(L, CQUEUE__POLL);
	lua_setfield(L, -2, "_POLL");

	/* add our version constants */
	lua_pushliteral(L, CQUEUES_VENDOR);
	lua_setfield(L, -2, "VENDOR");

	lua_pushinteger(L, CQUEUES_VERSION);
	lua_setfield(L, -2, "VERSION");

#if defined CQUEUES_COMMIT
	if (sizeof CQUEUES_COMMIT > 1) {
		lua_pushliteral(L, CQUEUES_COMMIT);
		lua_setfield(L, -2, "COMMIT");
	}
#endif

	return 1;
} /* luaopen__cqueues() */


/*
 * D E B U G  &  U N I T  T E S T I N G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int dbg_f2ms(lua_State *L) {
	int ms = f2ms(luaL_checknumber(L, 1));

	lua_pushinteger(L, ms);
	lua_pushboolean(L, ms == INT_MAX);

	return 2;
} /* dbg_f2ms() */

static int dbg_f2ts(lua_State *L) {
	struct timespec *ts = f2ts(luaL_checknumber(L, 1));

	if (!ts)
		return 0;

	lua_createtable(L, 0, 2);
	lua_pushinteger(L, ts->tv_sec);
	lua_setfield(L, -2, "tv_sec");
	lua_pushinteger(L, ts->tv_nsec);
	lua_setfield(L, -2, "tv_nsec");

	lua_pushboolean(L, ts->tv_sec == LONG_MAX);

	return 2;
} /* dbg_f2ts() */

static luaL_Reg dbg_globals[] = {
	{ "f2ms", &dbg_f2ms },
	{ "f2ts", &dbg_f2ts },
	{ NULL,   NULL }
}; /* dbg_globals[] */

int luaopen__cqueues_debug(lua_State *L) {
	luaL_newlib(L, dbg_globals);

	lua_pushinteger(L, INT_MAX);
	lua_setfield(L, -2, "INT_MAX");

	lua_pushinteger(L, LONG_MAX);
	lua_setfield(L, -2, "LONG_MAX");

	return 1;
} /* luaopen__cqueues_debug() */
