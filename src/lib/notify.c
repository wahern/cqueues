#include <limits.h>	/* NAME_MAX */
#include <stddef.h>	/* offsetof */
#include <stdlib.h>	/* calloc(3) free(3) */
#include <string.h>	/* memcpy(3) */
#include <errno.h>	/* ENAMETOOLONG EINTR EAGAIN EMFILE */
#include <string.h>	/* memcpy(3) strcmp(3) */

#include <unistd.h>	/* open(2) openat(2) close(2) */
#include <fcntl.h>	/* O_CLOEXEC */

#define HAVE_INOTIFY  (defined __linux__)
#define HAVE_FEN      (defined __sun)
#define HAVE_KQUEUE   (!HAVE_INOTIFY && !HAVE_FEN)
#define HAVE_KQUEUE1  (__NetBSD_Version__ >= 600000000)

#if HAVE_INOTIFY
#include <sys/inotify.h>
#elif HAVE_FEN
#include <sys/port.h>
#include <port.h>
#else
#include <sys/event.h>
#define xEV_SET(a, b, c, d, e, f) EV_SET((a), (b), (c), (d), (e), (__typeof__(((struct kevent)*0)->udata))(intptr_t)(f))
#endif

#include "llrb.h"


static int cloexec(int fd) {
	int flags;
	if (-1 == (flags = fcntl(F_GETFD, fd)))
		return errno;
	if (-1 == fcntl(F_SETFD, fd, flags|FD_CLOEXEC))
		return errno;
	return 0;
} /* cloexec() */


static int nonblock(int fd) {
	int flags;
	if (-1 == (flags = fcntl(F_GETFL, fd)))
		return errno;
	if (-1 == fcntl(F_SETFL, fd, flags|O_NONBLOCK))
		return errno;
	return 0;
} /* nonblock() */


static int closefd(int *fd) {
	while (*fd >= 0 && 0 != close(*fd)) {
		if (errno != EINTR)
			return errno;
	}

	*fd = -1;

	return 0;
} /* closefd() */


struct file {
#if !HAVE_INOTIFY
	int fd;
#endif

	LIST_ENTRY(file) le;
	LLRB_ENTRY(file) rbe;

	size_t namelen;
	char name[];
}; /* struct file */

static inline int filecmp(const struct file *a, const struct file *b)
	{ return strcmp(a->name, b->name); }


struct notify {
	int fd;

	LLRB_HEAD(files, file) files;
	LIST_HEAD(, file) dormant;
	LIST_HEAD(, file) pending;

	int dirfd;
	size_t dirlen;
	char dirpath[];
}; /* struct notify */


LLRB_GENERATE(files, file, rbe, filecmp)


static struct file *lookup(struct notify *N, const char *name) {
	struct file *key = (&(union { char pad[offsetof(struct file, name) + NAME_MAX + 1]; struct file file; }){ { 0 } })->file;
	size_t key->namelen = strlen(name);

	if (key->namelen > NAME_MAX)
		return NULL;

	memcpy(key->name, name, key->namelen);

	return LLRB_FIND(files, &N->files, key);
} /* lookup() */


struct notify *notify_open(const char *dir, int *error) {
	struct notify *N;
	size_t dirlen = strlen(dir);
	size_t padlen = NAME_LEN + 2;
	int flags;

	while (dirlen > 1 && dir[dirlen - 1] == '/')
		--dirlen;

	if (~padlen < dirlen) {
		error = ENAMETOOLONG;
		goto error;
	}

	if (!(N = calloc(1, offsetof(struct notify, path, dirlen + padlen))))
		goto syerr;

	N->fd = -1;

	N->dirfd = -1;
	N->dirlen = dirlen;
	memcpy(N->dirpath, dir, dirlen);

#if HAVE_INOTIFY
#if defined IN_NONBLOCK && defined IN_CLOEXEC
	if (-1 == (N->fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (N->fd = inotify_init()))
		goto syerr;

	if ((error = cloexec(N->fd)))
		goto error;

	if ((error = nonblock(N->fd)))
		goto error;
#endif

	if (-1 == inotify_add_watch(N->fd, N->dirpath, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR))
		goto syerr;
#elif HAVE_FEN
	if (-1 == (N->fd = port_create())) {
		if (errno == EAGAIN)
			errno = EMFILE;
		goto syerr;
	}

	if ((error = cloexec(N->fd)))
		goto error;
#else
#if HAVE_KQUEUE1
	if (-1 == (N->fd = kqueue1(O_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (N->fd = kqueue()))
		goto syerr;

	if ((error = cloexec(N->fd)))
		goto error;
#endif

#if defined O_CLOEXEC
	if (-1 == (N->dirfd = open(N->dirpath, O_RDONLY|O_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (N->dirfd = open(N->dirpath, O_RDONLY)))
		goto syerr;

	if ((error = cloexec(N->dirfd)))
		goto error;
#endif

	struct kevent event;

	xEV_SET(&event, N->dirfd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, N->dirfd);

	if (0 != kevent(N->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
		goto syerr;
#endif

	if ((error = cloexec(N->fd)))
		goto error;

	return N;
syerr:
	*error = errno;
error:
	notify_close(N);

	return NULL;
} /* notify_open() */


void notify_close(struct notify *N) {
	if (N) {
		closefd(&N->fd);
		closefd(&N->dirfd);
		free(N);
	}
} /* notify_close() */


int notify_add(struct notify *N, const char *name) {
	size_t namelen = strlen(name);
	struct file *file;

	if (namelen > NAME_MAX)
		return ENAMETOOLONG;

	if ((file = lookup(N, name)))
		return 0;

	return 0;
} /* notify_add() */

