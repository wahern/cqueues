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
#include "config.h"

#include <limits.h>	/* NAME_MAX */
#include <stddef.h>	/* offsetof */
#include <stdint.h>	/* intptr_t */
#include <stdlib.h>	/* calloc(3) free(3) */
#include <string.h>	/* memcpy(3) memchr(3) strcmp(3) */
#include <strings.h>	/* ffs(3) */
#include <errno.h>	/* ENAMETOOLONG EINTR EAGAIN EMFILE EISDIR ENOTDIR */

#include <sys/queue.h>	/* LIST_* */
#include <unistd.h>	/* close(2) */
#include <fcntl.h>	/* O_CLOEXEC O_DIRECTORY ... open(2) openat(2) fcntl(2) */
#include <dirent.h>	/* DIR fdopendir(3) opendir(3) readdir_r(3) closedir(3) */
#include <poll.h>	/* POLLIN poll(2) */

#include "notify.h"
#include "llrb.h"


/*
 * F E A T U R E  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef ENABLE_INOTIFY
#define ENABLE_INOTIFY HAVE_INOTIFY_INIT
#endif

#ifndef ENABLE_FEN
#define ENABLE_FEN HAVE_PORT_H
#endif

#ifndef ENABLE_KQUEUE
#define ENABLE_KQUEUE HAVE_KQUEUE
#endif

#ifndef HAVE_O_CLOEXEC
#define HAVE_O_CLOEXEC (defined O_CLOEXEC)
#endif

#ifndef HAVE_O_DIRECTORY
#define HAVE_O_DIRECTORY (defined O_DIRECTORY)
#endif

#ifndef HAVE_IN_CLOEXEC
#define HAVE_IN_CLOEXEC (defined IN_CLOEXEC)
#endif

#ifndef HAVE_IN_NONBLOCK
#define HAVE_IN_NONBLOCK (defined IN_NONBLOCK)
#endif

#if ENABLE_INOTIFY

#include <sys/inotify.h>

#elif ENABLE_FEN

#include <sys/stat.h>
#include <sys/port.h>
#include <port.h>

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#else

#include <sys/event.h>
#define NFY_SET(ev, id, filt, fl, ffl, d, ud) EV_SET((ev), (id), (filt), (fl), (ffl), (d), (__typeof__(((struct kevent *)0)->udata))(intptr_t)(ud))

#endif


int notify_features(void) {
	return 0
#if ENABLE_INOTIFY
	| NOTIFY_INOTIFY
#endif
#if ENABLE_FEN
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


const char *notify_strflag(int flag) {
	static const char *table[32] = {
		[0] = "CREATE", "ATTRIB", "MODIFY", "REVOKE", "DELETE",
		[16] = "inotify", "FEN", "kqueue", "kqueue1", "openat",
		       "fdopendir", "O_CLOEXEC", "IN_CLOEXEC",
	};

	return (ffs(0xFFFFFFFF & flag))? table[ffs(0xFFFFFFFF & flag) - 1] : NULL;
} /* notify_strflag() */


/*
 * D I A G N O S T I C S  &  D E B U G G I N G
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if __GNUC__ || __clang__
#define NOTUSED __attribute__((unused))
#else
#define NOTUSED
#endif

#if __clang__
#pragma clang diagnostic ignored "-Winitializer-overrides"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-label"
#elif (__GNUC__ == 4 && __GNUC_MINOR__ >= 6) || __GNUC__ > 4
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-label"
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

#define NFY_LIST_MOVE(head, elm, le) do { \
	LIST_REMOVE((elm), le); \
	LIST_INSERT_HEAD((head), (elm), le); \
} while (0)


/*
 * F I L E  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int cloexec(int fd) {
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFD)))
		return errno;
	if (-1 == fcntl(fd, F_SETFD, flags|FD_CLOEXEC))
		return errno;
	return 0;
} /* cloexec() */


static int nonblock(int) NOTUSED;

static int nonblock(int fd) {
	int flags;
	if (-1 == (flags = fcntl(fd, F_GETFL)))
		return errno;
	if (-1 == fcntl(fd, F_SETFL, flags|O_NONBLOCK))
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
#if HAVE_O_CLOEXEC
	if (opts->cloexec)
		flags |= O_CLOEXEC;
#endif
#if HAVE_O_DIRECTORY
	if (opts->directory)
		flags |= O_DIRECTORY;
#endif

	if (opts->dirfd >= 0) {
#if HAVE_OPENAT
		if (-1 == (fd = openat(opts->dirfd, opts->path, flags, opts->mode)))
			goto syerr;
#else
		if (opts->chdir) {
#if HAVE_O_CLOEXEC
			if (-1 == (wd = open(".", O_RDONLY|O_CLOEXEC)))
				goto syerr;
#else
			if (-1 == (wd = open(".", O_RDONLY)))
				goto syerr;
#endif

			if (0 != fchdir(opts->dirfd))
				goto syerr;

			error = (-1 == (fd = open(opts->path, flags, opts->mode)))? errno : 0;

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


#if ENABLE_FEN
static void fenfo_init(struct file_obj *fo, char *path) {
	struct stat st;

	if (0 == stat(path, &st)) {
		fo->fo_atime = st.st_atim;
		fo->fo_mtime = st.st_mtim;
		fo->fo_ctime = st.st_ctim;
	}

	fo->fo_name = path;
} /* fenfo_init() */
#endif


/*
 * N O T I F I C A T I O N  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct file {
	int fd;

#if ENABLE_FEN
	struct file_obj fo;
#endif

	int flags, changes, error;

	enum status {
		S_DEFUNCT = 0,
		S_POLLING = 1,
		S_REVOKED = 2,
		S_DELETED = 3,
	} status;

	LIST_ENTRY(file) le, sle;
	LLRB_ENTRY(file) rbe;

#if ENABLE_FEN
	char *name;
	size_t namelen;

	size_t pathlen;
	char path[];
#else
	size_t namelen;
	char name[];
#endif
}; /* struct file */

static inline int filecmp(const struct file *a, const struct file *b)
	{ return strcmp(a->name, b->name); }


struct notify {
	int fd;

	LLRB_HEAD(files, file) files;

	LIST_HEAD(, file) dormant;
	LIST_HEAD(, file) pending;
	LIST_HEAD(, file) changed;

	LIST_HEAD(, file) defunct;
	LIST_HEAD(, file) polling;
	LIST_HEAD(, file) revoked;
	LIST_HEAD(, file) deleted;

	int flags, changes;

	_Bool dirty;

#if ENABLE_INOTIFY
	_Bool critical;
#endif

#if ENABLE_FEN
	struct file_obj dirfo;
#endif

	int dirfd, dirwd;
	size_t dirlen;
	char dirpath[];
}; /* struct notify */


LLRB_GENERATE_STATIC(files, file, rbe, filecmp)


static struct file *lookup(struct notify *nfy, const char *name, size_t namelen) {
#if ENABLE_FEN
	struct file key = { .name = (char *)name, .namelen = namelen };

	return LLRB_FIND(files, &nfy->files, &key);
#else
	struct file *key = &((union { char pad[offsetof(struct file, name) + NAME_MAX + 1]; struct file file; }){ { 0 } }).file;

	if (namelen > NAME_MAX)
		return NULL;

	memcpy(key->name, name, namelen);
	key->namelen = namelen;

	return LLRB_FIND(files, &nfy->files, key);
#endif
} /* lookup() */


static void change(struct notify *nfy, struct file *file, int changes) {
	if (changes & file->flags) {
		file->changes |= (file->flags & changes);
		NFY_LIST_MOVE(&nfy->changed, file, le);
	}
} /* change() */


static void status(struct notify *nfy, struct file *file, enum status status) {
	switch (status) {
	case S_DEFUNCT:
		NFY_LIST_MOVE(&nfy->defunct, file, sle);
		break;
	case S_POLLING:
		NFY_LIST_MOVE(&nfy->polling, file, sle);

		if (file->status != status)
			change(nfy, file, (file->status == S_REVOKED)? NOTIFY_ATTRIB : NOTIFY_CREATE);

		break;
	case S_REVOKED:
		NFY_LIST_MOVE(&nfy->revoked, file, sle);

		if (file->status != status)
			change(nfy, file, NOTIFY_REVOKE);

		break;
	case S_DELETED:
		NFY_LIST_MOVE(&nfy->deleted, file, sle);

		if (file->status != status)
			change(nfy, file, NOTIFY_DELETE);

		break;
	} /* switch() */

	file->status = status;
} /* status() */


static void discard(struct notify *nfy, struct file *file) {
	closefd(&file->fd);

#if ENABLE_FEN
	port_dissociate(nfy->fd, PORT_SOURCE_FILE, (intptr_t)&file->fo);
#endif

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

#if ENABLE_INOTIFY
#if HAVE_INOTIFY_INIT1 && HAVE_IN_NONBLOCK && HAVE_IN_CLOEXEC
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

	if (-1 == (nfy->dirwd = inotify_add_watch(nfy->fd, nfy->dirpath, IN_ATTRIB|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MODIFY|IN_MOVE|IN_MOVE_SELF|IN_ONLYDIR)))
		goto syerr;
#elif ENABLE_FEN
	if (-1 == (nfy->fd = port_create())) {
		if (errno == EAGAIN)
			errno = EMFILE;
		goto syerr;
	}

	if ((error = cloexec(nfy->fd)))
		goto error;

	if ((error = nfy_openfd(&nfy->dirfd, .path = nfy->dirpath, .rdonly = 1, .cloexec = 1, .directory = 1)))
		goto error;

	fenfo_init(&nfy->dirfo, nfy->dirpath);

	if (0 != port_associate(nfy->fd, PORT_SOURCE_FILE, (intptr_t)&nfy->dirfo, FILE_MODIFIED|FILE_ATTRIB|FILE_NOFOLLOW, nfy))
		goto syerr;
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

	NFY_SET(&event, nfy->dirfd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, nfy);

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

		discard(nfy, file);
	}

	closefd(&nfy->fd);
	closefd(&nfy->dirfd);

#if ENABLE_FEN
	port_dissociate(nfy->fd, PORT_SOURCE_FILE, (intptr_t)&nfy->dirfo);
#endif

	free(nfy);
} /* notify_close() */


int notify_pollfd(struct notify *nfy) {
	return nfy->fd;
} /* notify_pollfd() */


int notify_timeout(struct notify *nfy) {
	if (nfy->dirty || !LIST_EMPTY(&nfy->pending) || !LIST_EMPTY(&nfy->changed))
		return 0;
	else
		return -1;
} /* notify_timeout() */


static int decode(int flags) {
#if ENABLE_INOTIFY
	static const int table[][2] = {
		{ IN_ATTRIB,      NOTIFY_ATTRIB },
		{ IN_CREATE,      NOTIFY_CREATE },
		{ IN_DELETE,      NOTIFY_DELETE },
		{ IN_DELETE_SELF, NOTIFY_DELETE },
		{ IN_MODIFY,      NOTIFY_MODIFY },
		{ IN_MOVE_SELF,   NOTIFY_DELETE },
		{ IN_MOVED_FROM,  NOTIFY_DELETE },
		{ IN_MOVED_TO,    NOTIFY_CREATE },
	};
#elif ENABLE_FEN
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

#define ms2ts(ms) (((ms) >= 0)? &(struct timespec){ (ms) / 1000, (((ms) % 1000) * 1000000) } : NULL)


#if ENABLE_INOTIFY
#define NFY_STEP in_step
#define NFY_POST in_post

#define IN_BUFSIZ 2048
#define in_msgbuf(bufsiz) (&((union { char pad[bufsiz]; struct inotify_event event; }){ { 0 } }).event)
#define in_msgend(msg, len) (struct inotify_event *)((unsigned char *)(msg) + (len))
#define in_msgnxt(msg) (struct inotify_event *)((unsigned char *)(msg) + offsetof(struct inotify_event, name) + (msg)->len)

static int in_step1(struct notify *nfy) {
	struct inotify_event *buf, *msg, *end;
	ssize_t len;
	int count = 0;

	buf = in_msgbuf(IN_BUFSIZ);

	while ((len = read(nfy->fd, buf, IN_BUFSIZ)) > 0) {
		for (msg = buf, end = in_msgend(buf, len); msg < end; msg = in_msgnxt(msg)) {
			size_t namelen = strlen(msg->name);

			if (namelen) {
				struct file *file;

				if ((file = lookup(nfy, msg->name, namelen))) {
					file->changes |= decode(msg->mask);
					NFY_LIST_MOVE(&nfy->pending, file, le);
				}
			} else {
				nfy->changes |= decode(msg->mask);
				nfy->dirty = 1;

				if (msg->mask & (IN_Q_OVERFLOW|IN_IGNORED|IN_UNMOUNT))
					nfy->critical = 1;
			}

			if (msg->mask & (IN_CREATE|IN_DELETE|IN_MOVE)) {
				nfy->changes |= decode(msg->mask & (IN_CREATE|IN_DELETE|IN_MOVE));
				nfy->dirty = 1;
			}

			++count;
		}

		if (count >= NOTIFY_MAXSTEP)
			return 0;
	}

	if (count > 0)
		return 0;
	else if (len == 0)
		return EPIPE;
	else
		return errno;
} /* in_step1() */


static int in_step(struct notify *nfy, int timeout) {
	int error;

	if (!(error = in_step1(nfy)))
		return 0;
	else if (error != EAGAIN)
		goto error;
	else if (timeout == 0)
		return 0;

	if (-1 == poll(&(struct pollfd){ nfy->fd, POLLIN, 0 }, 1, timeout))
		goto syerr;

	if ((error = in_step1(nfy)))
		goto error;

	return 0;
syerr:
	error = errno;
error:
	switch (error) {
	case EINTR:
		/* FALL THROUGH */
	case EAGAIN:
		return 0;
	default:
		return error;
	}
} /* in_step() */


static int in_post(struct notify *nfy) {
	struct file *file, *next;

	for (file = LIST_FIRST(&nfy->pending); file; file = next) {
		next = LIST_NEXT(file, le);

		file->changes &= file->flags;

		if (file->changes)
			NFY_LIST_MOVE(&nfy->changed, file, le);
		else
			NFY_LIST_MOVE(&nfy->dormant, file, le);
	}

	nfy->dirty = 0;
	nfy->changes &= nfy->flags;

	return 0;
} /* in_post() */


#elif ENABLE_FEN
#define NFY_STEP fen_step
#define NFY_POST fen_post

static int fen_step(struct notify *nfy, int timeout) {
	port_event_t event[NOTIFY_MAXSTEP];
	uint_t count = 1, i;
	int error;

	if (0 != port_getn(nfy->fd, event, countof(event), &count, ms2ts(timeout)))
		goto syerr;

	for (i = 0; i < count; i++) {
		if (event[i].portev_source != PORT_SOURCE_FILE)
			continue;

		if (event[i].portev_user == nfy) {
			nfy->changes |= decode(event[i].portev_events);
			nfy->dirty = 1;
		} else {
			struct file *file = event[i].portev_user;
			file->changes |= decode(event[i].portev_events);
			NFY_LIST_MOVE(&nfy->pending, file, le);
		}
	}

	return 0;
syerr:
	error = errno;

	switch (error) {
	case ETIME:
		/* FALL THROUGH */
	case EINTR:
		return 0;
	default:
		return error;
	}
} /* fen_step() */


static int fen_readd(struct notify *nfy, struct file *file) {
	int events, error;

	fenfo_init(&file->fo, file->path);

	events = FILE_ATTRIB|FILE_NOFOLLOW;

	if (file->flags & NOTIFY_MODIFY)
		events |= FILE_MODIFIED;

	error = port_associate(nfy->fd, PORT_SOURCE_FILE, (intptr_t)&file->fo, events, file)? errno : 0;

	switch (error) {
	case 0:
		status(nfy, file, S_POLLING);

		return 0;
	case ENOENT:
		status(nfy, file, S_DELETED);

		return 0;
	case EACCES:
		status(nfy, file, S_REVOKED);

		return 0;
	default:
		status(nfy, file, S_DEFUNCT);

		return file->error = error;
	}
} /* fen_readd() */


static int fen_post(struct notify *nfy) {
	struct file *file, *next;
	int error;

	for (file = LIST_FIRST(&nfy->pending); file; file = next) {
		next = LIST_NEXT(file, le);

		if ((error = fen_readd(nfy, file)))
			goto error;

		file->changes &= file->flags;

		if (file->changes)
			NFY_LIST_MOVE(&nfy->changed, file, le);
		else
			NFY_LIST_MOVE(&nfy->dormant, file, le);
	}

	if (nfy->dirty) {
		for (file = LIST_FIRST(&nfy->revoked); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = fen_readd(nfy, file)))
				return error;
		}

		for (file = LIST_FIRST(&nfy->deleted); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = fen_readd(nfy, file)))
				return error;
		}

		fenfo_init(&nfy->dirfo, nfy->dirpath);

		if (0 != port_associate(nfy->fd, PORT_SOURCE_FILE, (intptr_t)&nfy->dirfo, FILE_MODIFIED|FILE_ATTRIB|FILE_NOFOLLOW, nfy))
			goto syerr;

		nfy->changes &= nfy->flags;
		nfy->dirty = 0;
	}

	return 0;
syerr:
	error = errno;
error:
	return error;
} /* fen_post() */

#else
#define NFY_STEP kq_step
#define NFY_POST kq_post

static int kq_step(struct notify *nfy, int timeout) {
	struct kevent event[NOTIFY_MAXSTEP];
	struct file *file;
	int i, count;

	if (-1 == (count = kevent(nfy->fd, NULL, 0, event, countof(event), ms2ts(timeout))))
		return errno;

	for (i = 0; i < count; i++) {
		if ((void *)event[i].udata == nfy) {
			nfy->changes |= decode(event[i].fflags);
			nfy->dirty = 1;
		} else {
			file = (void *)event[i].udata;
			file->changes |= decode(event[i].fflags);
			NFY_LIST_MOVE(&nfy->pending, file, le);
		}
	}

	return 0;
} /* kq_step() */


static int kq_readd(struct notify *nfy, struct file *file) {
	struct kevent event;
	int notes, error;

	closefd(&file->fd);

	nfy->dirpath[nfy->dirlen] = '/';
	memcpy(&nfy->dirpath[nfy->dirlen + 1], file->name, file->namelen);
	nfy->dirpath[nfy->dirlen + 1 + file->namelen] = '\0';

	error = nfy_openfd(&file->fd, .dirfd = nfy->dirfd, .path = file->name, .abspath = nfy->dirpath, .rdonly = 1, .cloexec = 1, .nofollow = 1);

	nfy->dirpath[nfy->dirlen] = '\0';

	switch (error) {
	case 0:
		notes = NOTE_DELETE|NOTE_ATTRIB|NOTE_RENAME|NOTE_REVOKE;

		if (file->flags & NOTIFY_MODIFY)
			notes |= NOTE_WRITE|NOTE_EXTEND;

		NFY_SET(&event, file->fd, EVFILT_VNODE, EV_ADD|EV_CLEAR, notes, 0, file);

		if (0 != kevent(nfy->fd, &event, 1, NULL, 0, &(struct timespec){ 0, 0 })) {
			error = errno;
			goto error;
		}

		status(nfy, file, S_POLLING);

		return 0;
	case ENOENT:
		status(nfy, file, S_DELETED);

		return 0;
	case EACCES:
		status(nfy, file, S_REVOKED);

		return 0;
	default:
error:
		status(nfy, file, S_DEFUNCT);

		return file->error = error;
	}
} /* kq_readd() */


static int kq_post(struct notify *nfy) {
	struct file *file, *next;
	struct kevent event;
	int error;

	for (file = LIST_FIRST(&nfy->pending); file; file = next) {
		next = LIST_NEXT(file, le);

		if (file->changes & (NOTIFY_DELETE|NOTIFY_REVOKE)) {
			if ((error = kq_readd(nfy, file)))
				return error;
		}

		file->changes &= file->flags;

		if (file->changes)
			NFY_LIST_MOVE(&nfy->changed, file, le);
		else
			NFY_LIST_MOVE(&nfy->dormant, file, le);
	}

	if (nfy->dirty) {
		for (file = LIST_FIRST(&nfy->revoked); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = kq_readd(nfy, file)))
				return error;
		}

		for (file = LIST_FIRST(&nfy->deleted); file; file = next) {
			next = LIST_NEXT(file, sle);

			if ((error = kq_readd(nfy, file)))
				return error;
		}

		NFY_SET(&event, nfy->dirfd, EVFILT_VNODE, EV_ADD|EV_CLEAR, NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_REVOKE, 0, nfy);

		if (0 != kevent(nfy->fd, &event, 1, NULL, 0, ms2ts(0)))
			return errno;

		nfy->changes &= nfy->flags;
		nfy->dirty = 0;
	}

	return 0;
} /* kq_post() */
#endif


int notify_step(struct notify *nfy, int timeout) {
	int error;

	if (nfy->dirty || !LIST_EMPTY(&nfy->pending))
		goto post;

	if (nfy->changes || !LIST_EMPTY(&nfy->changed))
		return 0;

	if ((error = NFY_STEP(nfy, timeout)))
		return error;

post:
	if ((error = NFY_POST(nfy)))
		return error;

	return 0;
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

#if ENABLE_FEN
	size_t pathlen = nfy->dirlen + 1 + namelen;

	if (!(file = calloc(1, offsetof(struct file, path) + pathlen + 1)))
		return errno;

	memcpy(file->path, nfy->dirpath, nfy->dirlen);
	file->path[nfy->dirlen] = '/';
	file->pathlen = pathlen;
	file->name = &file->path[nfy->dirlen + 1];

	fenfo_init(&file->fo, file->path);
#else
	if (!(file = calloc(1, offsetof(struct file, name) + namelen + 1)))
		return errno;
#endif

	file->fd = -1;
	file->flags = flags;
	memcpy(file->name, name, namelen);
	file->namelen = namelen;

	LIST_INSERT_HEAD(&nfy->dormant, file, le);
	LIST_INSERT_HEAD(&nfy->defunct, file, sle);
	LLRB_INSERT(files, &nfy->files, file);

#if ENABLE_KQUEUE
	if ((error = kq_readd(nfy, file)))
		goto error;

	NFY_LIST_MOVE(&nfy->dormant, file, le);
	nfy->changes = 0;
#elif ENABLE_FEN
	if ((error = fen_readd(nfy, file)))
		goto error;

	NFY_LIST_MOVE(&nfy->dormant, file, le);
	nfy->changes = 0;
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
	int changes;

	if ((file = LIST_FIRST(&nfy->changed))) {
		NFY_LIST_MOVE(&nfy->dormant, file, le);

		if (name)
			*name = file->name;

		changes = file->changes;
		file->changes = 0;

		return changes;
	}

	if (!nfy->dirty && nfy->changes) {
		if (name)
			*name = ".";

		changes = nfy->changes;
		nfy->changes = 0;

		return changes;
	}

	return 0;
} /* notify_get() */


#if NOTIFY_MAIN

#include <stdio.h>
#include <err.h>


#define USAGE \
	"notify [-fh] [DIR [FILE ...]]\n" \
	"  -f  print kernel notification features\n" \
	"  -h  print usage message\n" \
	"\n" \
	"Report bugs to <william@25thandClement.com>\n"

static void printfeat(void) {
	int features = notify_features();
	int flag;

	while (features) {
		flag = 1 << (ffs(features) - 1);
		printf("%s\n", notify_strflag(flag));
		features &= ~flag;
	}
} /* printfeat() */

int main(int argc, char **argv) {
	extern int optind;
	const char *path;
	struct notify *notify;
	const char *file;
	int optc, i, error;

	while (-1 != (optc = getopt(argc, argv, "fh"))) {
		switch (optc) {
		case 'f':
			printfeat();
			return 0;
		case 'h':
			fputs(USAGE, stdout);
			return 0;
		default:
			fputs(USAGE, stderr);
			return EXIT_FAILURE;
		}
	} /* while() */

	argc -= optind;
	argv += optind;

	path = (argc > 0)? argv[0] : "/tmp";

	if (!(notify = notify_opendir(path, NOTIFY_ALL, &error)))
		errx(1, "%s: %s", path, strerror(error));

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
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
