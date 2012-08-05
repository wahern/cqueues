/* ==========================================================================
 * cqueues.c - Lua Continuation Queues
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
#include <limits.h>	/* INT_MAX LONG_MAX */

#include <stddef.h>	/* NULL offsetof() size_t */
#include <stdlib.h>	/* malloc(3) free(3) */

#include <string.h>	/* memset(3) strerror(3) */

#include <time.h>	/* struct timespec clock_gettime(3) */

#include <errno.h>	/* errno */

#include <sys/queue.h>	/* LIST */
#include <sys/time.h>	/* struct timeval */

#include <unistd.h>	/* close(2) */

#include <fcntl.h>	/* F_SETFD FD_CLOEXEC fcntl(2) */

#include <poll.h>	/* POLLIN POLLOUT */

#include <math.h>	/* NAN isnormal(3) isfinite(3) signbit(3) islessequal(3) isgreater(3) */

#include <lua.h>
#include <lauxlib.h>

#include "lib/llrb.h"


/*
 * V E R S I O N  I N T E R F A C E S
 *
 * If forking change CQUEUES_VENDOR to avoid confusion.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define CQUEUES_VENDOR "william@25thandClement.com"
#define CQUEUES_VERSION 20120805L


/*
 * D E B U G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")

#if __GNUC__
#define NOTUSED __attribute__((unused))
#else
#define NOTUSED
#endif

#if (__GNUC__ == 4 && __GNUC_MINOR__ >= 5) || __GNUC__ > 4
#define NOTREACHED __builtin_unreachable()
#else
#define NOTREACHED (void)0
#endif

#if __GNUC__
#define luaL_error(...) ({ int tmp = luaL_error(__VA_ARGS__); NOTREACHED; tmp; })
#endif


/*
 * U T I L I T Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define MIN(a, b) (((a) < (b))? (a) : (b))
#define MAX(a, b) (((a) > (b))? (a) : (b))

#define countof(a) (sizeof (a) / sizeof *(a))


static int setcloexec(int fd) {
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
 * OS X doesn't implement the clock_gettime() POSIX interface, but does
 * provide a monotonic clock through mach_absolute_time(). On i386 and
 * x86_64 architectures this clock is in nanosecond units, but not so on
 * other devices. mach_timebase_info() provides the conversion parameters.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#if __APPLE__

#include <time.h>            /* struct timespec */

#include <errno.h>           /* errno EINVAL */

#include <sys/time.h>        /* TIMEVAL_TO_TIMESPEC struct timeval gettimeofday(3) */

#include <mach/mach_time.h>  /* mach_timebase_info_data_t mach_timebase_info() mach_absolute_time() */


#define CLOCK_REALTIME  0
#define CLOCK_VIRTUAL   1
#define CLOCK_PROF      2
#define CLOCK_MONOTONIC 3

static mach_timebase_info_data_t clock_timebase = {
	.numer = 1, .denom = 1,
}; /* clock_timebase */

void clock_gettime_init(void) __attribute__((constructor));

void clock_gettime_init(void) {
	if (mach_timebase_info(&clock_timebase) != KERN_SUCCESS)
		__builtin_abort();
} /* clock_gettime_init() */

static int clock_gettime(int clockid, struct timespec *ts) {
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

#endif /* __APPLE__ */


static inline int f2ms(const double f) {
	if (isnormal(f) && !signbit(f)) {
		if (f > INT_MAX / 1000)
			return INT_MAX;

		return ((int)f * 1000) + ((int)(f * 1000.0) % 1000);
	} else if (f == 0.0) {
		return 0;
	} else
		return -1;
} /* f2ms() */

static inline struct timespec *f2ts_(struct timespec *ts, const double f) {
	if (isnormal(f) && !signbit(f)) {
		if ((time_t)f > INT_MAX) {
			ts->tv_sec = (time_t)INT_MAX;
			ts->tv_nsec = 0;
		} else {
			ts->tv_sec = (time_t)f;
			ts->tv_nsec = (long)(f * 1000000000.0) % 1000000000L;
		}

		return ts;
	} else if (f == 0.0) {
		return ts;
	} else
		return NULL;
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
	return (isfinite(timeout))? monotime() + timeout : NAN;
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

#define HAVE_KQUEUE __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __APPLE__
#define HAVE_EPOLL __linux__
#define HAVE_PORTS __sun

#if HAVE_EPOLL
#include <sys/epoll.h>	/* struct epoll_event epoll_create(2) epoll_ctl(2) epoll_wait(2) */
#elif HAVE_PORTS
#include <port.h>
#else
#include <sys/event.h>	/* EVFILT_READ EVFILT_WRITE EV_SET EV_ADD EV_DELETE struct kevent kqueue(2) kevent(2) */
#endif


#define KPOLL_FOREACH(ke, kp) for (ke = (kp)->pending.event; ke < &(kp)->pending.event[(kp)->pending.count]; ke++)

#define KPOLL_MAXWAIT 32

#if HAVE_EPOLL
typedef struct epoll_event kpoll_event_t;
#elif HAVE_PORTS
typedef port_event_t kpoll_event_t;
#else
/* NetBSD uses intptr_t, others use void *, for .udata */
#define KP_P2UDATA(p) ((__typeof__(((struct kevent *)0)->udata))(p))
#define KP_UDATA2P(udata) ((void *)(udata))
#define KP_SET(ev, a, b, c, d, e, f) EV_SET((ev), (a), (b), (c), (d), (e), KP_P2UDATA(f))

typedef struct kevent kpoll_event_t;
#endif

struct kpoll {
	int fd;

	struct {
		kpoll_event_t event[KPOLL_MAXWAIT];
		size_t count;
	} pending;
}; /* struct kpoll */


static void kpoll_preinit(struct kpoll *kp) {
	kp->fd = -1;
	kp->pending.count = 0;
} /* kpoll_preinit() */


static int kpoll_init(struct kpoll *kp) {
	int error;

#if HAVE_EPOLL
#if defined EPOLL_CLOEXEC
	if (-1 == (kp->fd = epoll_create1(EPOLL_CLOEXEC)))
		return errno;

	return 0;
#else
	if (-1 == (kp->fd = epoll_create(32)))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;

	return 0;
#endif
#elif HAVE_PORTS
	if (-1 == (kp->fd = port_create()))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;

	return 0;
#else
	if (-1 == (kp->fd = kqueue()))
		return errno;

	if ((error = setcloexec(kp->fd)))
		return error;

	return 0;
#endif	

} /* kpoll_init() */


static void kpoll_destroy(struct kpoll *kp) {
	(void)close(kp->fd);
	kpoll_preinit(kp);
} /* kpoll_destroy() */


static inline void *kpoll_udata(const kpoll_event_t *event) {
#if HAVE_EPOLL
	return event->data.ptr;
#elif HAVE_PORTS
	return event->portev_user;
#else
	return KP_UDATA2P(event->udata);
#endif
} /* kpoll_udata() */


static inline short kpoll_pending(const kpoll_event_t *event) {
#if HAVE_EPOLL
	return event->events;
#elif HAVE_PORTS
	return event->portev_events;
#else
	return (event->filter == EVFILT_READ)? POLLIN : (event->filter == EVFILT_WRITE)? POLLOUT : 0;
#endif
} /* kpoll_pending() */


static inline short kpoll_diff(const kpoll_event_t *event NOTUSED, short ostate NOTUSED) {
#if HAVE_PORTS
	/* Solaris Event Ports aren't persistent. */
	return 0;
#else
	return ostate;
#endif
} /* kpoll_diff() */


static int kpoll_ctl(struct kpoll *kp, int fd, short *state, short events, void *udata) {
#if HAVE_EPOLL
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
#elif HAVE_PORTS
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
#else
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


static int kpoll_wait(struct kpoll *kp, double timeout) {
#if HAVE_EPOLL
	int n;

	if (-1 == (n = epoll_wait(kp->fd, kp->pending.event, (int)countof(kp->pending.event), f2ms(timeout))))
		return (errno == EINTR)? 0 : errno;

	kp->pending.count = n;

	return 0;
#elif HAVE_PORTS
	kpoll_event_t *ke;
	uint_t n = 1;

	kp->pending.count = 0;

	if (0 != port_getn(kp->fd, kp->pending.event, countof(kp->pending.event), &n, f2ts(timeout)))
		return (errno == ETIME || errno == EINTR)? 0 : errno;

	kp->pending.count = n;

	return 0;
#else
	int n;

	if (-1 == (n = kevent(kp->fd, NULL, 0, kp->pending.event, (int)countof(kp->pending.event), f2ts(timeout))))
		return (errno == EINTR)? 0 : errno;

	kp->pending.count = n;

	return 0;
#endif
} /* kpoll_wait() */


/*
 * E P H E M E R O N  T A B L E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define CQUEUE_CLASS "Continuation Queue"

typedef int luaref_t;

struct event;
struct thread;
struct fileno;
struct cqueue;


struct event {
	int fd;
	short events;
	double timeout;

	_Bool pending;

	int index;

	struct thread *thread;
	LIST_ENTRY(event) tle;

	struct fileno *fileno;
	LIST_ENTRY(event) fle;
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
	luaref_t ref;
	lua_State *L; /* only for coroutines */

	LIST_HEAD(, event) events;
	unsigned count;

	LIST_ENTRY(thread) le;

	double mintimeout;

	struct timer timer;
}; /* struct thread */

#define timer2thread(timer) ((struct thread *)((char *)(timer) - offsetof(struct thread, timer)))


struct cqueue {
	struct kpoll kp;

	luaref_t registry; /* ephemeron table global registry index */

	struct {
		LLRB_HEAD(table, fileno) table;
		LIST_HEAD(, fileno) polling, outstanding, inactive;
	} fileno;

	struct {
		struct pool fileno, thread, event;
	} pool;

	struct {
		LIST_HEAD(, thread) polling, pending;
		unsigned count;
	} thread;

	LLRB_HEAD(timers, timer) timers;
}; /* struct cqueue */


static inline int fileno_cmp(const struct fileno *const a, const struct fileno *const b) {
	return a->fd - b->fd;
} /* filno_cmp() */

LLRB_GENERATE(table, fileno, rbe, fileno_cmp)


static inline int timer_cmp(const struct timer *const a, const struct timer *const b) {
	return (a->timeout < b->timeout)? -1 : (a->timeout > b->timeout)? 1 : (a < b)? -1 : (a > b)? 1 : 0;
} /* timer_cmp() */

LLRB_GENERATE(timers, timer, rbe, timer_cmp)


struct callinfo {
	int self; /* stack index of cqueue object */
	int registry; /* stack index of ephemeron registry table */
}; /* struct callinfo */


static struct cqueue *cqueue_enter(lua_State *L, struct callinfo *I, int index) {
	struct cqueue *Q = luaL_checkudata(L, index, CQUEUE_CLASS);

	I->self = lua_absindex(L, index);

	lua_rawgeti(L, LUA_REGISTRYINDEX, Q->registry);
	lua_pushvalue(L, I->self);
	lua_gettable(L, -2);
	lua_replace(L, -2);
	I->registry = lua_absindex(L, -1);

	return Q;
} /* cqueue_enter() */


static int cqueue_ref(lua_State *L, struct callinfo *I, int index) {
	lua_pushvalue(L, index);
	return luaL_ref(L, I->registry);
} /* cqueue_ref() */


static void cqueue_unref(lua_State *L, struct callinfo *I, luaref_t *ref) {
	luaL_unref(L, I->registry, *ref);
	*ref = LUA_NOREF;
} /* cqueue_unref() */


static void cqueue_preinit(struct cqueue *Q) {
	memset(Q, 0, sizeof *Q);

	kpoll_preinit(&Q->kp);

	Q->registry = LUA_NOREF;

	pool_init(&Q->pool.fileno, sizeof (struct fileno));
	pool_init(&Q->pool.thread, sizeof (struct thread));
	pool_init(&Q->pool.event, sizeof (struct event));
} /* cqueue_preinit() */


static void cqueue_init(lua_State *L, struct cqueue *Q, int index) {
	int error;

	index = lua_absindex(L, index);

	if ((error = kpoll_init(&Q->kp)))
		luaL_error(L, "unable to initialize continuation queue: %s", strerror(error));

	/*
	 * create ephemeron table
	 */
	lua_newtable(L);
	lua_newtable(L);
	lua_pushstring(L, "k");
	lua_setfield(L, -2, "__mode");
	lua_setmetatable(L, -2);

	/*
	 * create our registry table, indexed in our ephemeron table by
	 * a reference to our self.
	 */
	lua_pushvalue(L, index);
	lua_newtable(L);
	lua_settable(L, -3);

	/*
	 * anchor our ephemeron table in the global registry
	 */
	Q->registry = luaL_ref(L, LUA_REGISTRYINDEX);
} /* cqueue_init() */


static void thread_del(lua_State *, struct cqueue *, struct callinfo *, struct thread *);
static int fileno_del(struct cqueue *, struct fileno *, _Bool);

static void cqueue_destroy(lua_State *L, struct cqueue *Q, struct callinfo *I) {
	struct thread *thread;
	struct fileno *fileno;
	void *next;

	while ((thread = LIST_FIRST(&Q->thread.polling))) {
		thread_del(L, Q, I, thread);
	}

	for (fileno = LLRB_MIN(table, &Q->fileno.table); fileno; fileno = next) {
		next = LLRB_NEXT(table, &Q->fileno.table, fileno);
		fileno_del(Q, fileno, 0);
	}

	kpoll_destroy(&Q->kp);

	pool_destroy(&Q->pool.fileno);
	pool_destroy(&Q->pool.thread);
	pool_destroy(&Q->pool.event);

	luaL_unref(L, LUA_REGISTRYINDEX, Q->registry);
	Q->registry = LUA_NOREF;
} /* cqueue_destroy() */


static int cqueue_new(lua_State *L) {
	struct cqueue *Q;

	Q = lua_newuserdata(L, sizeof *Q);

	cqueue_preinit(Q);

	luaL_getmetatable(L, CQUEUE_CLASS);
	lua_setmetatable(L, -2);

	cqueue_init(L, Q, -1);

	return 1;
} /* cqueue_new() */


static int cqueue__gc(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;

	Q = cqueue_enter(L, &I, 1);

	cqueue_destroy(L, Q, &I);

	return 0;
} /* cqueue__gc() */


static struct fileno *fileno_get(struct cqueue *Q, int fd, int *error) {
	struct fileno key, *fileno;

	key.fd = fd;

	if (!(fileno = LLRB_FIND(table, &Q->fileno.table, &key))) {
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


static int fileno_update(struct cqueue *Q, struct fileno *fileno) {
	struct event *event;
	short events = 0;
	int error;

	LIST_FOREACH(event, &fileno->events, fle) {
		events |= event->events;
	}

	if ((error = kpoll_ctl(&Q->kp, fileno->fd, &fileno->state, events, fileno)))
		return error;

	LIST_REMOVE(fileno, le);

	if (fileno->state)
		LIST_INSERT_HEAD(&Q->fileno.polling, fileno, le);
	else
		LIST_INSERT_HEAD(&Q->fileno.inactive, fileno, le);

	return 0;
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


static int object_pcall(lua_State *L, int index, const char *field, int rtype) {
	int status;

	index = lua_absindex(L, index);

	lua_getfield(L, index, field);

	if (lua_isfunction(L, -1)) {
		lua_pushvalue(L, index);

		if (LUA_OK != (status = lua_pcall(L, 1, 1, 0)))
			return status;

		if (!lua_isnil(L, -1) && lua_type(L, -1) != rtype) {
			lua_pushfstring(L, "%s method: %s expected, got %s", field, lua_typename(L, rtype), luaL_typename(L, -1));

			return LUA_ERRRUN;
		}
	} else {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return LUA_OK;
} /* object_pcall() */


static int object_getinfo(lua_State *L, struct thread *T, int index, struct event *event) {
	int status;
	const char *mode;

	lua_pushvalue(T->L, index);
	lua_xmove(T->L, L, 1);

	if (LUA_OK != (status = object_pcall(L, -1, "pollfd", LUA_TNUMBER)))
		goto error;

	event->fd = luaL_optinteger(L, -1, -1);

	lua_pop(L, 1); /* pop fd */

	if (LUA_OK != (status = object_pcall(L, -1, "events", LUA_TSTRING)))
		goto error;

	mode = luaL_optstring(L, -1, "");
	event->events = 0;

	while (*mode) {
		if (*mode == 'r')
			event->events |= POLLIN;
		else if (*mode == 'w')
			event->events |= POLLOUT;
		mode++;
	}

	lua_pop(L, 1); /* pop event mode */

	if (LUA_OK != (status = object_pcall(L, -1, "timeout", LUA_TNUMBER)))
		goto error;

	event->timeout = abstimeout(luaL_optnumber(L, -1, NAN));

	lua_pop(L, 1); /* pop timeout */

	lua_pop(L, 1); /* pop object */

	return LUA_OK;
error:
	return status;
} /* object_getinfo() */


static void event_init(struct event *event, struct thread *T, int index) {
	memset(event, 0, sizeof *event);

	event->fd = -1;
	event->timeout = NAN;

	event->index = index;

	LIST_INSERT_HEAD(&T->events, event, tle);
	event->thread = T;
} /* event_init() */


static int event_add(lua_State *L, struct cqueue *Q, struct thread *T, int index) {
	struct event *event;
	struct fileno *fileno;
	int error, status;

	if (!(event = pool_get(&Q->pool.event, &error)))
		goto error;

	event_init(event, T, index);

	if (LUA_OK != (status = object_getinfo(L, T, index, event)))
		return status;

	if (event->fd != -1 && event->events) {
		if (!(fileno = fileno_get(Q, event->fd, &error)))
			goto error;

		LIST_INSERT_HEAD(&fileno->events, event, fle);
		event->fileno = fileno;

		LIST_REMOVE(fileno, le);
		LIST_INSERT_HEAD(&Q->fileno.outstanding, fileno, le);
	}

	return LUA_OK;
error:
	lua_pushfstring(L, "internal error in continuation queue: %s", strerror(error));

	return LUA_ERRRUN;
} /* event_add() */


static void event_del(struct cqueue *Q, struct event *event) {
	if (event->fileno) {
		LIST_REMOVE(event->fileno, le);
		LIST_INSERT_HEAD(&Q->fileno.outstanding, event->fileno, le);

		LIST_REMOVE(event, fle);
	}

	LIST_REMOVE(event, tle);

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

	LIST_FOREACH(event, &T->events, tle) {
		timeout = mintimeout(timeout, event->timeout);
	}

	return timeout;
} /* thread_timeout() */


static void thread_add(lua_State *L, struct cqueue *Q, struct callinfo *I, int index) {
	struct thread *T;
	int error;

	index = lua_absindex(L, index);

	if (!(T = pool_get(&Q->pool.thread, &error)))
		luaL_error(L, "internal error in continuation queue: %s", strerror(error));

	memset(T, 0, sizeof *T);

	T->ref = LUA_NOREF;
	LIST_INIT(&T->events);

	timer_init(&T->timer);

	T->ref = cqueue_ref(L, I, index);
	T->L = lua_tothread(L, index);

	LIST_INSERT_HEAD(&Q->thread.pending, T, le);
	Q->thread.count++;
} /* thread_add() */


static void thread_del(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T) {
	struct event *event;

	while ((event = LIST_FIRST(&T->events))) {
		event_del(Q, event);
	}

	timer_destroy(Q, &T->timer);

	cqueue_unref(L, I, &T->ref);
	T->L = NULL;

	LIST_REMOVE(T, le);
	Q->thread.count--;

	pool_put(&Q->pool.thread, T);
} /* thread_del() */


static int cqueue_update(lua_State *L, struct cqueue *Q) {
	struct fileno *fileno, *next;
	int error;

	for (fileno = LIST_FIRST(&Q->fileno.outstanding); fileno; fileno = next) {
		next = LIST_NEXT(fileno, le);

		if ((error = fileno_update(Q, fileno)))
			goto error;
	}

	return LUA_OK;
error:
	lua_pushfstring(L, "internal error in continuation queue: %s", strerror(error));

	return LUA_ERRRUN;
} /* cqueue_update() */


static void luacq_xcopy(lua_State *from, lua_State *to, int count) {
	int index;

	for (index = 1; index <= count; index++)
		lua_pushvalue(from, index);

	lua_xmove(from, to, count);
} /*  luacq_xcopy() */


static void luacq_slice(lua_State *L, int index, int count) {
	if (index + count == lua_gettop(L) + 1) {
		lua_pop(L, count);
	} else {
		while (count--)
			lua_remove(L, index);
	}
} /* luacq_slice() */


static int cqueue_resume(lua_State *L, struct cqueue *Q, struct callinfo *I, struct thread *T) {
	int otop, ntmp, nargs, status, index;
	struct event *event;

	/*
	 * Preserve any previously yielded objects on another stack until we
	 * can call cqueue_update() because when lua_resume() returns the
	 * thread stack will only contain new objects. Pausing the GC isn't
	 * a viable option because we don't know if or when lua_resume()
	 * will return.
	 */
	otop  = lua_gettop(L);
	ntmp = (lua_status(T->L) == LUA_YIELD)? lua_gettop(T->L) : 0;
	luacq_xcopy(T->L, L, ntmp);

	nargs = 0;

	while((event = LIST_FIRST(&T->events))) {
		if (event->pending) {
			lua_pushvalue(T->L, event->index);
			nargs++;
		}

		event_del(Q, event);
	}

	timer_del(Q, &T->timer);

	switch ((status = lua_resume(T->L, L, nargs))) {
	case LUA_YIELD:
		for (index = 1; index <= lua_gettop(T->L); index++) {
			if (LUA_OK != (status = event_add(L, Q, T, index)))
				goto error;
		}

		if (LUA_OK != (status = cqueue_update(L, Q)))
			goto error;

		timer_add(Q, &T->timer, thread_timeout(T));

		if (!LIST_EMPTY(&T->events) || isfinite(T->timer.timeout)) {
			LIST_REMOVE(T, le);
			LIST_INSERT_HEAD(&Q->thread.polling, T, le);
		}

		break;
	case LUA_OK:
		if (LUA_OK != (status = cqueue_update(L, Q)))
			goto error;

		thread_del(L, Q, I, T);

		break;
	default:
		if (LUA_OK != cqueue_update(L, Q))
			goto error;

		lua_xmove(T->L, L, 1);
error:
		thread_del(L, Q, I, T);

		break;
	} /* switch() */

	luacq_slice(L, otop + 1, ntmp);

	return status;
} /* cqueue_resume() */


static int cqueue_process(lua_State *L, struct cqueue *Q, struct callinfo *I) {
	kpoll_event_t *ke;
	struct fileno *fileno;
	struct event *event;
	struct thread *T, *nxt;
	struct timer *timer;
	double curtime;
	short events;
	int status;

	KPOLL_FOREACH(ke, &Q->kp) {
		fileno = kpoll_udata(ke);
		events = kpoll_pending(ke);

		LIST_FOREACH(event, &fileno->events, fle) {
			if (event->events & events)
				event->pending = 1;

			LIST_REMOVE(event->thread, le);
			LIST_INSERT_HEAD(&Q->thread.pending, event->thread, le);
		}

		fileno->state = kpoll_diff(ke, fileno->state);
	}

	curtime = monotime();

	LLRB_FOREACH(timer, timers, &Q->timers) {
		if (isgreater(timer->timeout, curtime))
			break;

		T = timer2thread(timer);

		LIST_FOREACH(event, &T->events, tle) {
			if (islessequal(event->timeout, curtime))
				event->pending = 1;
		}

		LIST_REMOVE(T, le);
		LIST_INSERT_HEAD(&Q->thread.pending, T, le);
	}

	for (T = LIST_FIRST(&Q->thread.pending); T; T = nxt) {
		nxt = LIST_NEXT(T, le);

		if (LUA_OK != (status = cqueue_resume(L, Q, I, T)))
			return status;
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

static int cqueue_step(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q; 
	double timeout;
	int error;

	lua_settop(L, 2);

	Q = cqueue_enter(L, &I, 1);

	if (LIST_EMPTY(&Q->thread.pending)) {
		timeout = mintimeout(luaL_optnumber(L, 2, NAN), cqueue_timeout_(Q));
	} else
		timeout = 0.0;

	if ((error = kpoll_wait(&Q->kp, timeout)))
		return luaL_error(L, "internal error in continuation queue: %s", strerror(error));

	if (LUA_OK != cqueue_process(L, Q, &I)) {
		lua_pushboolean(L, 0);
		lua_pushvalue(L, -2);

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* cqueue_step() */


static int cqueue_attach(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;

	lua_settop(L, 2);

	Q = cqueue_enter(L, &I, 1);
	luaL_checktype(L, 2, LUA_TTHREAD);

	thread_add(L, Q, &I, 2);

	lua_pushboolean(L, 1);

	return 1;
} /* cqueue_attach() */


static int cqueue_wrap(lua_State *L) {
	struct callinfo I;
	struct cqueue *Q;
	struct lua_State *newL;

	lua_settop(L, 2);

	Q = cqueue_enter(L, &I, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);

	newL = lua_newthread(L);
	lua_pushvalue(L, 2);
	lua_xmove(L, newL, 1);

	thread_add(L, Q, &I, -1);

	lua_pushboolean(L, 1);

	return 1;
} /* cqueue_wrap() */


static int cqueue_empty(lua_State *L) {
	struct cqueue *Q = luaL_checkudata(L, 1, CQUEUE_CLASS);

	lua_pushboolean(L, !Q->thread.count);

	return 1;
} /* cqueue_empty() */


static int cqueue_count(lua_State *L) {
	struct cqueue *Q = luaL_checkudata(L, 1, CQUEUE_CLASS);

	lua_pushnumber(L, Q->thread.count);

	return 1;
} /* cqueue_count() */


static int cqueue_pollfd(lua_State *L) {
	struct cqueue *Q = luaL_checkudata(L, 1, CQUEUE_CLASS);

	lua_pushinteger(L, Q->kp.fd);

	return 1;
} /* cqueue_pollfd() */


static int cqueue_events(lua_State *L) {
	luaL_checkudata(L, 1, CQUEUE_CLASS);

	lua_pushliteral(L, "r");

	return 1;
} /* cqueue_events() */


static int cqueue_timeout(lua_State *L) {
	struct cqueue *Q = luaL_checkudata(L, 1, CQUEUE_CLASS);

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


static int cqueue_interpose(lua_State *L) {
	luaL_getmetatable(L, CQUEUE_CLASS);
	lua_getfield(L, -1, "__index");
	
	lua_pushvalue(L, -4); /* push method name */
	lua_gettable(L, -2);  /* push old method */
			
	lua_pushvalue(L, -5); /* push method name */
	lua_pushvalue(L, -5); /* push new method */
	lua_settable(L, -4);  /* replace old method */

	return 1; /* return old method */
} /* cqueue_interpose() */


static int cqueue_monotime(lua_State *L) {
	lua_pushnumber(L, monotime());

	return 1;
} /* cqueue_monotime() */


static const luaL_Reg cqueue_methods[] = {
	{ "step",    &cqueue_step },
	{ "attach",  &cqueue_attach },
	{ "wrap",    &cqueue_wrap },
	{ "empty",   &cqueue_empty },
	{ "count",   &cqueue_count },
	{ "pollfd",  &cqueue_pollfd },
	{ "events",  &cqueue_events },
	{ "timeout", &cqueue_timeout },
	{ NULL,      NULL }
}; /* cqueue_methods[] */


static const luaL_Reg cqueue_metatable[] = {
	{ "__gc", &cqueue__gc },
	{ NULL,   NULL }
}; /* cqueue_metatable[] */


static const luaL_Reg cqueues_globals[] = {
	{ "new",       &cqueue_new },
	{ "interpose", &cqueue_interpose },
	{ "monotime",  &cqueue_monotime },
	{ NULL,        NULL }
}; /* cqueues_globals[] */


int luaopen__cqueues(lua_State *L) {
	if (luaL_newmetatable(L, CQUEUE_CLASS)) {
		luaL_setfuncs(L, cqueue_metatable, 0);

		luaL_newlib(L, cqueue_methods);
		lua_setfield(L, -2, "__index");
	}

	lua_pop(L, 1);

	luaL_newlib(L, cqueues_globals);

	lua_pushliteral(L, CQUEUES_VENDOR);
	lua_setfield(L, -2, "VENDOR");

	lua_pushnumber(L, CQUEUES_VERSION);
	lua_setfield(L, -2, "VERSION");

#if defined CQUEUES_COMMIT
	if (sizeof CQUEUES_COMMIT > 1) {
		lua_pushliteral(L, CQUEUES_COMMIT);
		lua_setfield(L, -2, "COMMIT");
	}
#endif

	return 1;
} /* luaopen__cqueues() */

