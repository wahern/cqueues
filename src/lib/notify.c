/* ==========================================================================
 * notify.c - Kernel File Notification.
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
#include <limits.h>	/* NAME_MAX */
#include <stddef.h>	/* offsetof */
#include <stdlib.h>	/* calloc(3) free(3) */
#include <string.h>	/* memcpy(3) memchr(3) strcmp(3) */
#include <strings.h>	/* ffs(3) */
#include <errno.h>	/* ENAMETOOLONG EINTR EAGAIN EMFILE EISDIR ENOTDIR */

#include <sys/queue.h>	/* LIST_* */
#include <unistd.h>	/* close(2) */
#include <fcntl.h>	/* O_CLOEXEC O_DIRECTORY ... open(2) openat(2) fcntl(2) */
#include <dirent.h>	/* DIR fdopendir(3) opendir(3) readdir_r(3) closedir(3) */

#include "notify.h"
#include "llrb.h"


/*
 * F E A T U R E  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define HAVE_INOTIFY    (defined __linux__)
#define HAVE_FEN        (defined __sun)
#define HAVE_KQUEUE     (!HAVE_INOTIFY && !HAVE_FEN)
#define HAVE_KQUEUE1    (__NetBSD_Version__ >= 600000000)
#define HAVE_OPENAT     (!__NetBSD__ && !__APPLE__)
#define HAVE_FDOPENDIR  (!__NetBSD__ && !__APPLE__)
#define HAVE_O_CLOEXEC  (defined O_CLOEXEC)
#define HAVE_IN_CLOEXEC (defined IN_CLOEXEC)

#if HAVE_INOTIFY
#include <sys/inotify.h>
#elif HAVE_FEN
#include <sys/port.h>
#include <port.h>
#else
#include <sys/event.h>
#define xEV_SET(ev, id, filt, fl, ffl, d, ud) EV_SET((ev), (id), (filt), (fl), (ffl), (d), (__typeof__(((struct kevent *)0)->udata))(intptr_t)(ud))
#endif


int notify_features(void) {
	return 0
#if HAVE_INOTIFY
	| NOTIFY_INOTIFY
#endif
#if HAVE_FEN
	| NOTIFY_FEN
#endif
#if HAVE_KQUEUE
	| NOTIFY_KQUEUE
#endif
#if HAVE_KQUEUE1
	| NOTIFY_KQUEUE1
#endif
#if HAVE_OPENAT
	| NOTIFY_OPENAT
#endif
#if HAVE_FDOPENDIR
	| NOTIFY_FDOPENDIR
#endif
#if HAVE_O_CLOEXEC
	| NOTIFY_O_CLOEXEC
#endif
#if HAVE_IN_CLOEXEC
	| NOTIFY_IN_CLOEXEC
#endif
	;
} /* notify_features() */


const char *notify_strfeature(int flag) {
	static const char *table[16] = {
		"inotify", "fen", "kqueue", "kqueue1", "openat", "fdopendir",
		"o_cloexec", "in_cloexec",
	};

	return (ffs(0xFFFF0000 & flag))? table[ffs(0xFFFF0000 & flag) - 17] : NULL;
} /* notify_strfeature() */


/*
 * D I A G N O S T I C S  &  D E B U G G I N G
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define NOTUSED __attribute__((unused))

#if __clang__
#pragma clang diagnostic ignored "-Winitializer-overrides"
#pragma clang diagnostic ignored "-Wunused-function"
#elif (__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ > 4
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <stdio.h>

#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")


/*
 * M A C R O  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define countof(a) (sizeof (a) / sizeof *(a))

#define LIST_MOVE(head, elm, le) do { \
	LIST_REMOVE((elm), le); \
	LIST_INSERT_HEAD((head), (elm), le); \
} while (0)


/*
 * F I L E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int cloexec(int fd) {
	int flags;
	if (-1 == (flags = fcntl(F_GETFD, fd)))
		return errno;
	if (-1 == fcntl(F_SETFD, fd, flags|FD_CLOEXEC))
		return errno;
	return 0;
} /* cloexec() */


static int nonblock(int) NOTUSED;

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


#define nfy_openfd(fd, ...) nfy_openfd((fd), &(struct nfy_open){ .dirfd = -1, __VA_ARGS__ })

struct nfy_open {
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

static int (nfy_openfd)(int *_fd, const struct nfy_open *opts) {
	int fd = -1, wd = -1, flags = 0;
	int error;

	if (opts->rdwr)	
		flags |= O_RDWR;
	else if (opts->wronly)
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
#if HAVE_OPENAT
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
		if (-1 == (fd = open(opts->path, flags, opts->mode)))
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
} /* nfy_openfd() */


#if 0
static DIR *nfy_opendir(const char *path, int *error) {
	DIR *dir;
#if HAVE_FDOPENDIR
#else
#endif
	return dir;
} /* nfy_opendir() */
#endif


/*
 * N O T I F I C A T I O N  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct file {
	int fd;

	int flags, events, error;

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

	int flags, events;

	int dirfd, dirwd;
	size_t dirlen;
	char dirpath[];
}; /* struct notify */


LLRB_GENERATE(files, file, rbe, filecmp)


static struct file *lookup(struct notify *nfy, const char *name, size_t namelen) {
	struct file *key = &((union { char pad[offsetof(struct file, name) + NAME_MAX + 1]; struct file file; }){ { 0 } }).file;

	if (namelen > NAME_MAX)
		return NULL;

	memcpy(key->name, name, key->namelen);
	key->namelen = namelen;

	return LLRB_FIND(files, &nfy->files, key);
} /* lookup() */


static void status(struct notify *nfy, struct file *file, enum status status) {
	switch (file->status = status) {
	case S_DEFUNCT:
		LIST_MOVE(&nfy->defunct, file, sle);
		break;
	case S_REGULAR:
		LIST_MOVE(&nfy->regular, file, sle);
		break;
	case S_REVOKED:
		LIST_MOVE(&nfy->revoked, file, sle);
		break;
	case S_DELETED:
		LIST_MOVE(&nfy->deleted, file, sle);
		break;
	} /* switch() */
} /* status() */


static int reopen(struct notify *nfy, struct file *file) {
	int error;

	closefd(&file->fd);

	status(nfy, file, S_DEFUNCT);

	nfy->dirpath[nfy->dirlen] = '/';
	memcpy(&nfy->dirpath[nfy->dirlen + 1], file->name, file->namelen);
	nfy->dirpath[nfy->dirlen + 1 + file->namelen] = '\0';

	error = nfy_openfd(&file->fd, .dirfd = nfy->dirfd, .path = file->name, .abspath = nfy->dirpath, .rdonly = 1, .cloexec = 1, .nofollow = 1);

	nfy->dirpath[nfy->dirlen] = '\0';

	switch (error) {
	case 0:
		status(nfy, file, S_REGULAR);

		break;
	case ENOENT:
		status(nfy, file, S_DELETED);

		break;
	case EPERM:
		status(nfy, file, S_REVOKED);

		break;
	default:
		goto error;
	}

	return 0;
error:
	return file->error = error;
} /* reopen() */


static int process(struct notify *nfy, struct file *file) {
	int error;

	if ((file->events & (NOTIFY_DELETE|NOTIFY_REVOKE)) || file->fd == -1) {
		if ((error = reopen(nfy, file)))
			goto error;
	}

	if (file->fd != -1) {
		struct kevent event;

		xEV_SET(&event, file->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_RENAME|NOTE_REVOKE, 0, file);

		if (0 != kevent(nfy->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
			goto syerr;
	}

	return 0;
syerr:
	error = errno;
error:
	file->error = error;

	status(nfy, file, S_DEFUNCT);

	return error;
} /* process() */


static void discard(struct notify *nfy, struct file *file) {
	closefd(&file->fd);

	LLRB_REMOVE(files, &nfy->files, file);
	LIST_REMOVE(file, le);
	LIST_REMOVE(file, sle);

	free(file);
} /* discard() */


struct notify *notify_opendir(const char *dirpath, int flags, int *_error) {
	struct notify *nfy = NULL;
	size_t dirlen = strlen(dirpath);
	size_t padlen = NAME_MAX + 2;
	int error;

	while (dirlen > 1 && dirpath[dirlen - 1] == '/')
		--dirlen;

	if (~padlen < dirlen) {
		error = ENAMETOOLONG;
		goto error;
	}

	if (!(nfy = calloc(1, offsetof(struct notify, dirpath) + dirlen + padlen)))
		goto syerr;

	nfy->fd = -1;
	nfy->flags = flags;

	nfy->dirfd = -1;
	nfy->dirwd = -1;
	nfy->dirlen = dirlen;
	memcpy(nfy->dirpath, dirpath, dirlen);

#if HAVE_INOTIFY
#if defined IN_NONBLOCK && defined IN_CLOEXEC
	if (-1 == (nfy->fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (nfy->fd = inotify_init()))
		goto syerr;

	if ((error = cloexec(nfy->fd)))
		goto error;

	if ((error = nonblock(nfy->fd)))
		goto error;
#endif

	if (-1 == (nfy->dirwd = inotify_add_watch(nfy->fd, nfy->dirpath, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_MODIFY|IN_MOVE|IN_ONLYDIR)))
		goto syerr;
#elif HAVE_FEN
	if (-1 == (nfy->fd = port_create())) {
		if (errno == EAGAIN)
			errno = EMFILE;
		goto syerr;
	}

	if ((error = cloexec(nfy->fd)))
		goto error;
#else
#if HAVE_KQUEUE1 && HAVE_O_CLOEXEC
	if (-1 == (nfy->fd = kqueue1(O_CLOEXEC)))
		goto syerr;
#else
	if (-1 == (nfy->fd = kqueue()))
		goto syerr;

	if ((error = cloexec(nfy->fd)))
		goto error;
#endif

	if ((error = nfy_openfd(&nfy->dirfd, .path = nfy->dirpath, .rdonly = 1, .cloexec = 1, .directory = 1)))
		goto error;

	struct kevent event;

	xEV_SET(&event, nfy->dirfd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, nfy);

	if (0 != kevent(nfy->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 }))
		goto syerr;
#endif

	return nfy;
syerr:
	error = errno;
error:
	*_error = error;

	notify_close(nfy);

	return NULL;
} /* notify_opendir() */


void notify_close(struct notify *nfy) {
	struct file *file, *next;

	if (!nfy)
		return;

	for (file = LLRB_MIN(files, &nfy->files); file != NULL; file = next) {
		next = LLRB_NEXT(files, &nfy->files, file);

		LLRB_REMOVE(files, &nfy->files, file);
		LIST_REMOVE(file, le);
		LIST_REMOVE(file, sle);

		closefd(&file->fd);
		free(file);
	}

	closefd(&nfy->fd);
	closefd(&nfy->dirfd);

	free(nfy);
} /* notify_close() */


static int decode(int flags) {
#if HAVE_INOTIFY
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
#elif HAVE_FEN
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
	unsigned i;

	for (i = 0; i < countof(table); i++) {
		if (table[i][0] & flags)
			events |= table[i][1];
	}

	return events;
} /* decode() */


#define NOTIFY_MAXSTEP 32

int notify_step(struct notify *nfy, int timeout) {
#if HAVE_INOTIFY
	return 0;
#elif HAVE_FEN
	return 0;
#else
	struct kevent event[NOTIFY_MAXSTEP];
	struct timespec *ts = (timeout >= 0)? &(struct timespec){ timeout / 1000, ((timeout % 1000) * 1000000) } : NULL;
	struct file *file, *next;
	int i, count, error;

	if (-1 == (count = kevent(nfy->fd, NULL, 0, event, countof(event), ts)))
		return errno;

	for (i = 0; i < count; i++) {
		if ((void *)event[i].udata == nfy) {
			nfy->events |= decode(event[i].fflags);

			xEV_SET(&event[i], nfy->dirfd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, nfy);

			if (0 != kevent(nfy->fd, &event[i], 1, NULL, 0, &(struct timespec){ 0, 0 }))
				return errno;
		} else {
			file = (void *)event[i].udata;

			LIST_MOVE(&nfy->pending, file, le);

			file->events |= decode(event[i].fflags);
		}
	}

	for (i = 0; i < count; i++) {
		if ((void *)event[i].udata == nfy)
			continue;

		if ((error = process(nfy, (void *)event[i].udata)))
			return error;
	}

	if (nfy->events & (NOTIFY_MODIFY|NOTIFY_ATTRIB)) {
		for (file = LIST_FIRST(&nfy->revoked); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = process(nfy, file)))
				return error;

			if (file->status != S_REVOKED) {
				LIST_MOVE(&nfy->pending, file, le);
				file->events |= NOTIFY_ATTRIB;
			}
		}

		for (file = LIST_FIRST(&nfy->deleted); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = process(nfy, file)))
				return error;

			if (file->status != S_DELETED) {
				LIST_MOVE(&nfy->pending, file, le);
				file->events |= NOTIFY_CREATE;
			}
		}
	}

	return 0;
#endif
} /* notify_step() */


int notify_add(struct notify *nfy, const char *name, int flags) {
	size_t namelen = strlen(name);
	struct file *file;
	int error;

	if (namelen > NAME_MAX)
		return ENAMETOOLONG;
	if (memchr(name, '/', namelen))
		return EISDIR;

	if ((file = lookup(nfy, name, namelen)))
		return 0;

	if (!(file = calloc(1, offsetof(struct file, name) + namelen + 1)))
		return errno;

	file->fd = -1;
	file->flags = flags;
	memcpy(file->name, name, namelen);
	file->namelen = namelen;

	LIST_INSERT_HEAD(&nfy->dormant, file, le);
	LIST_INSERT_HEAD(&nfy->defunct, file, sle);
	LLRB_INSERT(files, &nfy->files, file);

#if HAVE_KQUEUE
	if ((error = process(nfy, file)))
		goto error;
#endif

	return 0;
error:
	discard(nfy, file);

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


int notify_get(struct notify *nfy, const char **name) {
	struct file *file;
	int events;

	if ((file = LIST_FIRST(&nfy->pending))) {
		LIST_MOVE(&nfy->dormant, file, le);

		if (name)
			*name = file->name;

		events = file->events;
		file->events = 0;

		return events;
	}

	return 0;
} /* notify_get() */


#if NOTIFY_MAIN

#include <stdio.h>
#include <err.h>

int main(int argc, char *argv[]) {
	const char *path = (argc > 1)? argv[1] : "/tmp";
	struct notify *notify;
	const char *file;
	int i, error;

	{
		int features = notify_features();
		int fl;

		while ((fl = ffs(features))) {
			fl = 1 << (fl - 1);
			printf("%s (0x%.6x)\n", notify_strfeature(fl), fl);
			features &= ~fl;
		}
	}


	if (!(notify = notify_opendir(path, NOTIFY_ALL, &error)))
		errx(1, "%s: %s", path, strerror(error));

	if (argc > 2) {
		for (i = 2; i < argc; i++) {
			if ((error = notify_add(notify, argv[i], NOTIFY_ALL)))
				errx(1, "%s: %s", argv[i], strerror(error));
		}
	} else if ((error = notify_add(notify, "test.file", NOTIFY_ALL)))
		errx(1, "test.file: %s", strerror(error));

	while (!(error = notify_step(notify, -1))) {
		while (notify_get(notify, &file))
			puts(file);
	}

	return 0;
} /* main() */

#endif
