/* ==========================================================================
 * notify.h - Kernel File Notification.
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
#ifndef NOTIFY_H
#define NOTIFY_H

#define NOTIFY_VERSION 0x20120926


#define NOTIFY_CREATE 0x01
#define NOTIFY_ATTRIB 0x02
#define NOTIFY_MODIFY 0x04
#define NOTIFY_REVOKE 0x08
#define NOTIFY_DELETE 0x10

#define NOTIFY_ALL (NOTIFY_CREATE|NOTIFY_DELETE|NOTIFY_ATTRIB|NOTIFY_MODIFY|NOTIFY_REVOKE)

#define NOTIFY_GLOB 0x20
#define NOTIFY_GREP 0x40


#define nfy_error_t int
#define nfy_timeout_t int
#define nfy_flags_t int


struct notify *notify_opendir(const char *, nfy_flags_t, nfy_error_t *);

void notify_close(struct notify *);

int notify_pollfd(struct notify *);

nfy_timeout_t notify_timeout(struct notify *);

nfy_error_t notify_step(struct notify *, nfy_timeout_t);

nfy_error_t notify_add(struct notify *, const char *, nfy_flags_t);

nfy_flags_t notify_get(struct notify *, const char **);


#define NOTIFY_INOTIFY    0x010000
#define NOTIFY_FEN        0x020000
#define NOTIFY_KQUEUE     0x040000
#define NOTIFY_KQUEUE1    0x080000
#define NOTIFY_OPENAT     0x100000
#define NOTIFY_FDOPENDIR  0x200000
#define NOTIFY_O_CLOEXEC  0x400000
#define NOTIFY_IN_CLOEXEC 0x800000

nfy_flags_t notify_features(void);

const char *notify_strflag(nfy_flags_t);


#endif /* NOTIFY_H */
