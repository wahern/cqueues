#include <limits.h>	/* INT_MAX LONG_MAX */

#include <stddef.h>	/* NULL size_t */
#include <stdlib.h>	/* malloc(3) free(3) */

#include <string.h>	/* memset(3) strerror(3) */

#include <time.h>	/* struct timespec clock_gettime(3) */

#include <errno.h>	/* errno */

#include <sys/queue.h>	/* LIST */
#include <sys/time.h>	/* struct timeval */

#include <unistd.h>	/* close(2) */

#include <fcntl.h>	/* F_SETFD FD_CLOEXEC fcntl(2) */

#include <poll.h>	/* POLLIN POLLOUT */

#include <math.h>	/* isnormal(3) signbit(3) */

#include <lua.h>
#include <lauxlib.h>

#include "llrb.h"




/*
 * U T I L I T Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define MIN(a, b) (((a) < (b))? (a) : (b))

#define countof(a) (sizeof (a) / sizeof *(a))


static int setcloexec(int fd) {
	if (-1 == fcntl(fd, F_SETFD, FD_CLOEXEC))
		return errno;
} /* setcloexec() */


/*
 * T I M E  &  C L O C K  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
		if (f > LONG_MAX / 1000) {
			ts->tv_sec = LONG_MAX;
			ts->tv_sec = LONG_MAX % 1000000000L;
		} else {
			ts->tv_sec = (long)f;
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
	return ts->tv_sec * (ts->tv_nsec / 1000000000.0);
} /* ts2f() */


static inline double tv2f(const struct timeval *tv) {
	return tv->tv_sec * (tv->tv_usec / 1000000.0);
} /* tv2f() */


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
	size_t size;
	void *head;
}; /* pool */

static void pool_init(struct pool *P, size_t size) {
	P->size = size;
	P->head = NULL;
} /* pool_init() */

static void pool_destroy(struct pool *P) {
	void *p;

	while ((p = P->head)) {
		P->head = *(void **)p;
		free(p);
	}
} /* pool_destroy() */

static void *pool_get(struct pool *P, int *error) {
	void *p;

	if (!(p = P->head))
		return make(P->size, error);

	P->head = *(void **)p;

	return p;
} /* pool_get() */

static void pool_put(struct pool *P, void *p) {
	*(void **)p = P->head;
	P->head = p;
} /* pool_put() */



/*
 * K P O L L  ( K Q U E U E / E P O L L )  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define HAVE_KQUEUE __FreeBSD__ || __NetBSD__ || __OpenBSD__ || __APPLE__
#define HAVE_EPOLL __linux__

#if HAVE_EPOLL
#include <sys/epoll.h>	/* struct epoll_event epoll_create(2) epoll_ctl(2) epoll_wait(2) */
#else
#include <sys/event.h>	/* EVFILT_READ EVFILT_WRITE EV_SET EV_ADD EV_DELETE struct kevent kqueue(2) kevent(2) */
#endif


#define KPOLL_MAXWAIT 32

#if HAVE_EPOLL
typedef struct epoll_event kpoll_event_t;
#else
typedef struct kevent kpoll_event_t;
#endif

struct kpoll {
	int fd;

	struct {
		kpoll_event_t event[KPOLL_MAXWAIT];
		size_t i, count;
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
#else
	struct kevent event;

	if (*state == events)
		return 0;

	if (events & POLLIN) {
		if (!(*state & POLLIN)) {
			EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, udata);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				return errno;

			*state |= POLLIN;
		}
	} else if (*state & POLLIN) {
		EV_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

		if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			return errno;

		*state &= ~POLLIN;
	}

	if (events & POLLOUT) {
		if (!(*state & POLLOUT)) {
			EV_SET(&event, fd, EVFILT_WRITE, EV_ADD, 0, 0, udata);

			if (0 != kevent(kp->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
				return errno;

			*state |= POLLOUT;
		}
	} else if (*state & POLLOUT) {
		EV_SET(&event, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

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
		return errno;

	kp->pending.count = n;
	kp->pending.i = 0;

	return 0;
#else
	int n;

	if (-1 == (n = kevent(kp->fd, NULL, 0, kp->pending.event, (int)countof(kp->pending.event), f2ts(timeout))))
		return errno;

	kp->pending.count = n;
	kp->pending.i = 0;

	return 0;
#endif
} /* kpoll_wait() */


static inline void *kpoll_udata(const kpoll_event_t *event) {
#if HAVE_EPOLL
	return event->data.ptr;
#else
	return event->udata;
#endif
} /* kpoll_udata() */


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
	short state;

	luaref_t object;

	struct thread *thread;
	LIST_ENTRY(thread) tle;

	struct fileno *fileno;
	LIST_ENTRY(fileno) fle;
}; /* struct event */


struct fileno {
	int fd;
	short state;

	LIST_HEAD(, luacq_event) events;

	struct luacq_queue *cqueue;

	LLRB_ENTRY(fileno) rbe;
}; /* struct fileno */


struct thread {
	struct cqueue *cqueue;

	enum {
		LUACQ_COROUTINE,
		LUACQ_CLOSURE,
	} type;

	luaref_t ref;
	lua_State *L; /* only for coroutines */

	LIST_HEAD(, event) events;
	LIST_ENTRY(thread) le;
}; /* struct thread */


struct cqueue {
	struct kpoll kp;

	luaref_t registry; /* ephemeron table global registry index */

	LLRB_HEAD(table, fileno) table;

	struct {
		struct pool fileno, thread;
	} pool;

	LIST_HEAD(, thread) polling, pending;
}; /* struct cqueue */


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
	kpoll_preinit(&Q->kp);

	Q->registry = LUA_NOREF;

	LLRB_INIT(&Q->table);

	pool_init(&Q->pool.fileno, sizeof (struct fileno));
	pool_init(&Q->pool.thread, sizeof (struct thread));
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


static void cqueue_destroy(lua_State *L, struct cqueue *Q) {
	kpoll_destroy(&Q->kp);

	pool_destroy(&Q->pool.fileno);
	pool_destroy(&Q->pool.thread);

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
	struct cqueue *Q = luaL_checkudata(L, 1, CQUEUE_CLASS);

	cqueue_destroy(L, Q);

	return 0;
} /* cqueue__gc() */


static int cqueue_attach(lua_State *L) {
	struct cqueue *Q;
	struct callinfo I;

	Q = cqueue_enter(L, &I, 1);
	luaL_checktype(L, 2, LUA_TTHREAD);

	
} /* cqueue_attach() */
