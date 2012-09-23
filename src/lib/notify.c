#include <limits.h>	/* NAME_MAX */
#include <stddef.h>	/* offsetof */
#include <stdlib.h>	/* calloc(3) free(3) */
#include <string.h>	/* memcpy(3) memchr(3) strcmp(3) */
#include <errno.h>	/* ENAMETOOLONG EINTR EAGAIN EMFILE EISDIR ENOTDIR */

#include <sys/queue.h>	/* LIST_* */
#include <unistd.h>	/* close(2) */
#include <fcntl.h>	/* O_CLOEXEC O_DIRECTORY ... open(2) openat(2) fcntl(2) */

#define NOTIFY_INOTIFY  (defined __linux__)
#define NOTIFY_FEN      (defined __sun)
#define NOTIFY_KQUEUE   (!NOTIFY_INOTIFY && !NOTIFY_FEN)
#define NOTIFY_KQUEUE1  (__NetBSD_Version__ >= 600000000)
#define NOTIFY_OPENAT   (__linux__ || __sun || __OpenBSD__ || __FreeBSD__ || __DragonFly__)

#if NOTIFY_INOTIFY
#include <sys/inotify.h>
#elif NOTIFY_FEN
#include <sys/port.h>
#include <port.h>
#else
#include <sys/event.h>
#define xEV_SET(a, b, c, d, e, f) EV_SET((a), (b), (c), (d), (e), (__typeof__(((struct kevent)*0)->udata))(intptr_t)(f))
#endif

#include "llrb.h"


#ifndef countof
#define countof(a) (sizeof (a) / sizeof *(a))
#endif

#define LIST_MOVE(head, elm, le) do { \
	LIST_REMOVE((elm), le); \
	LIST_INSERT_HEAD((head), (elm), le); \
} while (0)


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


#define openfd(fd, ...) openfd((fd), &(struct openopts){ .dirfd = -1, __VA_ARGS__ })

struct openopts {
	const char *path;
	const char *abspath;
	int dirfd;
	_Bool chdir;

	_Bool rdonly;
	_Bool rdwr;
	_Bool wronly;
	_Bool creat;
	_Bool trunc;
	_Bool nofollow;
	_Bool cloexec;
	_Bool directory;

	mode_t mode;
};

static int (openfd)(int *_fd, const struct openopts *opts) {
	int fd = -1, wd = -1, flags = 0;
	int error;

	if (opts->rdwr)	
		flags |= O_RDWR;
	else if (opt->wronly)
		flags |= O_WRONLY;
	else
		flags |= O_RDONLY;

	if (opts->creat)
		flags |= O_CREAT;
	if (opts->trunc)
		flags |= O_TRUNC;
	if (opts->nofollow)
		flags |= O_NOFOLLOW;
#if defined O_CLOEXEX
	if (opts->cloexec)
		flags |= O_CLOEXEC;
#endif
#if defined O_DIRETORY
	if (opts->directory)
		flags |= O_DIRECTORY;
#endif

	if (opts->dirfd >= 0) {
#if NOTIFY_OPENAT
		if (-1 == (fd = openat(opts->dirfd, opts->path, flags, opts->mode)))
			goto syerr;
#else
		if (opts->chdir) {
#if defined O_CLOEXEC
			if (-1 == (wd = open(".", O_RDONLY|O_CLOEXEC)))
				goto syerr;
#else
			if (-1 == (wd = open(".", O_RDONLY)))
				goto syerr;
#endif

			if (0 != fchdir(opts->dirfd))
				goto syerr;

			if (-1 == (fd = open(opts->path, flags, opts->mode)))
				error = errno;

			if (0 != fchdir(wd))
				goto syerr;

			if (fd == -1)
				goto error;

			if ((error = closefd(&wd)))
				goto error;
		} else {
			if (-1 == (fd = open(opts->abspath, flags, opts->mode)))
				goto syerr;
		}
#endif
	} else {
		if (-1 == (fd = open(path, flags, opts->mode)))
			goto syerr;
	}

#if !defined O_CLOEXEC
	if (opts->cloexec && (error = cloexec(fd)))
		goto error;
#endif

#if !defined O_DIRECTORY
	if (opts->directory) {
		struct stat st;

		if (0 != fstat(fd, &st))
			goto syerr;

		if (!S_ISDIR(st.st_mode)) {
			error = ENOTDIR;
			goto error;
		}
	}
#endif

	*_fd = fd;

	return 0;
syerr:
	error = errno;
error:
	closefd(&fd);
	closefd(&wd);

	return error;
} /* openfd() */



struct file {
	int fd;

	int events, error;

	enum status {
		S_DEFUNCT = 0,
		S_REGULAR = 1,
		S_REVOKED = 2,
		S_DELETED = 3,
	} status;

	LIST_ENTRY(file) le, sle;
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

	LIST_HEAD(, file) defunct;
	LIST_HEAD(, file) regular;
	LIST_HEAD(, file) revoked;
	LIST_HEAD(, file) deleted;

	int events;

	int dirfd, dirwd;
	size_t dirlen;
	char dirpath[];
}; /* struct notify */


LLRB_GENERATE(files, file, rbe, filecmp)


static struct file *lookup(struct notify *dir, const char *name, size_t namelen) {
	struct file *key = (&(union { char pad[offsetof(struct file, name) + NAME_MAX + 1]; struct file file; }){ { 0 } })->file;

	if (namelen > NAME_MAX)
		return NULL;

	memcpy(key->name, name, key->namelen);
	key->namelen = namelen;

	return LLRB_FIND(files, &dir->files, key);
} /* lookup() */


static void status(struct notify *dir, struct file *F, enum status status) {
	switch (F->status = status) {
	case S_DEFUNCT:
		LIST_MOVE(&dir->defunct);
		break;
	case S_REGULAR:
		LIST_MOVE(&dir->defunct);
		break;
	case S_REVOKED:
		LIST_MOVE(&dir->defunct);
		break;
	case S_DELETED:
		LIST_MOVE(&dir->defunct);
		break;
	} /* switch() */
} /* status() */


static int reopen(struct notify *dir, struct file *F) {
	struct kevent event;
	int error;

	closefd(&F->fd);

	status(dir, F, S_DEFUNCT);

	dir->dirpath[dir->dirlen] = '/';
	memcpy(&dir->dirpath[dir->dirlen + 1], file->name, file->namelen);
	dir->dirpath[dir->dirlen + 1 + file->namelen] = '\0';

	error = openfd(&file->fd, .dirfd = dir->dirfd, .path = file->name, .abspath = dir->dirpath, .rdonly = 1, .cloexec = 1, .nofollow = 1);

	dir->dirpath[dir->dirlen] = '\0';

	switch (error) {
	case 0:
		xEV_SET(&event, file->fd, EVFILT_VNODE, EV_ADD, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, file);

		if (0 != kevent(dir->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			goto syerr;

		status(dir, F, S_REGULAR);

		break;
	case ENOENT:
		status(dir, F, S_DELETED);

		break;
	case EPERM:
		status(dir, F, S_REVOKED);

		break;
	default:
		goto error;
	}

	return 0;
syerr:
	error = errno;
error:
	return F->error = error;
} /* reopen() */


static int process(struct notify *dir, struct file *file) {
	if (file->events & (NOTIFY_DELETE|NOTIFY_REVOKE)) {
		if ((error = reopen(dir, file)))
			return error;
	}

	return 0;
} /* process() */


static void discard(struct notify *dir, struct file *file) {
	closefd(&file->fd);

	LLRB_REMOVE(files, &dir->files, file);
	LIST_REMOVE(file, le);
	LIST_REMOVE(file, sle);

	free(file);
} /* discard() */


struct notify *notify_open(const char *dirpath, const struct notify_options *opts, int *_error) {
	struct notify *dir;
	size_t dirlen = strlen(dir);
	size_t padlen = NAME_LEN + 2;
	int error;

	while (dirlen > 1 && dir[dirlen - 1] == '/')
		--dirlen;

	if (~padlen < dirlen) {
		error = ENAMETOOLONG;
		goto error;
	}

	if (!(dir = calloc(1, offsetof(struct notify, path, dirlen + padlen))))
		goto syerr;

	dir->fd = -1;

	dir->dirfd = -1;
	dir->dirwd = -1;
	dir->dirlen = dirlen;
	memcpy(dir->dirpath, dir, dirlen);

#if NOTIFY_INOTIFY
#if defined IN_NONBLOCK && defined IN_CLOEXEC
	if (-1 == (dir->fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (dir->fd = inotify_init()))
		goto syerr;

	if ((error = cloexec(dir->fd)))
		goto error;

	if ((error = nonblock(dir->fd)))
		goto error;
#endif

	if (-1 == (dir->dirwd = inotify_add_watch(dir->fd, dir->dirpath, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR)))
		goto syerr;
#elif NOTIFY_FEN
	if (-1 == (dir->fd = port_create())) {
		if (errno == EAGAIN)
			errno = EMFILE;
		goto syerr;
	}

	if ((error = cloexec(dir->fd)))
		goto error;
#else
#if NOTIFY_KQUEUE1
	if (-1 == (dir->fd = kqueue1(O_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (dir->fd = kqueue()))
		goto syerr;

	if ((error = cloexec(dir->fd)))
		goto error;
#endif

	if ((error = openfd(&dir->dirfd, .path = dir->dirpath, .rdonly = 1, .cloexec = 1, .directory = 1)))
		goto error;

	struct kevent event;

	xEV_SET(&event, dir->dirfd, EVFILT_VNODE, EV_ADD, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, dir);

	if (0 != kevent(dir->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
		goto syerr;
#endif

	return dir;
syerr:
	error = errno;
error:
	*_error = error;

	notify_close(dir);

	return NULL;
} /* notify_open() */


void notify_close(struct notify *dir) {
	struct file *file, *next;

	if (!dir)
		return;

	for (file = LLRB_MIN(files, &dir->files); file != NULL; file = next) {
		next = LLRB_NEXT(files, &dir->files, file);

		LLRB_REMOVE(files, &dir->files, file);
		LIST_REMOVE(file, le);
		LIST_REMOVE(file, sle);

		closefd(&file->fd);
		free(file);
	}

	closefd(&dir->fd);
	closefd(&dir->dirfd);

	free(dir);
} /* notify_close() */


static int decode(int flags) {
#if NOTIFY_INOTIFY
	static const int table[][2] = {
		{ IN_ATTRIB,      NOTIFY_ATTRIB },
		{ IN_CREATE,      NOTIFY_CREATE },
		{ IN_DELETE,      NOTIFY_DELETE },
		{ IN_DELETE_SELF, NOTIFY_DELETE },
		{ IN_MODIFY,      NOTIFY_MODIFY },
		{ IN_MOVE_SELF,   NOTIFY_DELETE },
		{ IN_MOVE_FROM,   NOTIFY_DELETE },
		{ IN_MOVE_TO,     NOTIFY_CREATE },
	};
#elif NOTIFY_FEN
	static const int table[][2] = {
		{ FILE_MODIFIED,    NOTIFY_MODIFY },
		{ FILE_ATTRIB,      NOTIFY_ATTRIB },
		{ FILE_DELETE,      NOTIFY_DELETE },
		{ FILE_RENAME_TO,   NOTIFY_DELETE },
		{ FILE_RENAME_FROM, NOTIFY_DELETE },
	};
#else
	static const int table[][2] = {
		{ NOTE_DELETE, NOTIFY_DELETE },
		{ NOTE_WRITE,  NOTIFY_MODIFY },
		{ NOTE_EXTEND, NOTIFY_MODIFY },
		{ NOTE_ATTRIB, NOTIFY_ATTRIB },
		{ NOTE_LINK,   NOTIFY_ATTRIB },
		{ NOTE_RENAME, NOTIFY_DELETE },
		{ NOTE_REVOKE, NOTIFY_REVOKE },
	};
#endif
	int events = 0;

	for (unsigned i = 0; i < countof(table); i++) {
		if (table[i][0] & flags)
			events |= table[i][1];
	}

	return events;
} /* decode() */


#define NOTIFY_MAXSTEP 32

int notify_step(struct notify *dir) {
#if NOTIFY_INOTIFY
	return 0;
#elif NOTIFY_FEN
	return 0;
#else
	struct kevent event[NOTIFY_MAXSTEP];
	struct file *file;
	int count, error;
	int fflags = 0;

	if (-1 == (count = kevent(dir->fd, NULL, 0, event, countof(event), &(struct timespec){ 0, 0 })))
		return errno;

	for (int i = 0; i < count; i++) {
		if ((void *)event[i].udata == dir) {
			dir->events |= decode(event[i].fflags);
		} else {
			file = (void *)event[i].udata;

			LIST_MOVE(&N->pending, file, le);

			file->events |= decode(event[i].fflags);
		}
	}

	for (int i = 0; i < count; i++) {
		if ((void *)event[i].udata == dir)
			continue;

		if ((error = process(dir)))
			return error;
	}

	return 0;
#endif
} /* notify_step() */


int notify_add(struct notify *dir, const char *name) {
	size_t namelen = strlen(name);
	struct file *file;

	if (namelen > NAME_MAX)
		return ENAMETOOLONG;
	if (memchr(name, '/', namelen)
		return EISDIR;

	if ((file = lookup(dir, name, namelen)))
		return 0;

	if (!(file = calloc(1, offsetof(struct file, name) + namelen + 1)))
		return errno;

	file->fd = -1;
	memcpy(file->name, name, namelen)
	file->namelen = namelen;

	LIST_INSERT_HEAD(&dir->dormant, file, le);
	LIST_INSERT_HEAD(&dir->defunct, file, sle);
	LLRB_INSERT(files, &dir->files, file);

#if NOTIFY_KQUEUE
	if ((error = reopen(dir, file)))
		goto error;
#endif

	return 0;
error:
	discard(dir, file);

	return error;
} /* notify_add() */


static int notify_del(struct notify *dir, const char *name) {
	size_t namelen = strlen(name);
	struct file *file;

	if (namelen > NAME_MAX)
		return ENAMETOOLONG;

	if (!(file = lookup(dir, name, namelen)))
		return 0;

	discard(dir, file);

	return 0;
} /* notify_del() */


