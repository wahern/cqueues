#!/bin/sh
#
# List all EXXXX macros
#

set -e 

: ${CC:=cc}
: ${xflag:=}
: ${ELAST=no}


usage() {
	cat <<-EOF
	usage: $(basename $0) -lxh
	  -l  print or compute ELAST value
	  -x  expand macros
	  -h  print this usage message
	
	Report bugs to <william@25thandClement.com>
	EOF
}

while getopts lxh OPT; do
	case "${OPT}" in
	l)
		if [ -n "${xflag}" ]; then
			echo "$0: -l and -x are exclusive" >&2
			usage >&2
			exit 1
		fi

		ELAST=yes
		;;
	x)
		if [ "${ELAST}" != "no" ]; then
			echo "$0: -l and -x are exclusive" >&2
			usage >&2
			exit 1
		fi

		xflag="-x"
		;;
	h)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 1
		;;
	esac
done


posix() {
	cat <<-EOF | tr " " "\n"
		E2BIG EACCES EADDRINUSE EADDRNOTAVAIL EAFNOSUPPORT EAGAIN
		EWOULDBLOCK EALREADY EBADF EBADMSG EBUSY ECANCELED ECHILD
		ECONNABORTED ECONNREFUSED ECONNRESET EDEADLK EDESTADDRREQ
		EDOM EDQUOT EEXIST EFAULT EFBIG EHOSTUNREACH EIDRM EILSEQ
		EINPROGRESS EINTR EINVAL EIO EISCONN EISDIR ELOOP EMFILE
		EMLINK EMSGSIZE EMULTIHOP ENAMETOOLONG ENETDOWN ENETRESET
		ENETUNREACH ENFILE ENOBUFS ENODATA ENODEV ENOENT ENOEXEC
		ENOLCK ENOLINK ENOMEM ENOMSG ENOPROTOOPT ENOSPC ENOSR ENOSTR
		ENOSYS ENOTCONN ENOTDIR ENOTEMPTY ENOTRECOVERABLE ENOTSOCK
		ENOTSUP EOPNOTSUPP ENOTTY ENXIO EOPNOTSUPP ENOTSUP EOVERFLOW
		EOWNERDEAD EPERM EPIPE EPROTO EPROTONOSUPPORT EPROTOTYPE
		ERANGE EROFS ESPIPE ESRCH ESTALE ETIME ETIMEDOUT ETXTBSY
		EWOULDBLOCK EAGAIN EXDEV
	EOF
}

errno_h() {
	posix | env PATH="$(dirname $0):${PATH}" CC="${CC}" macros.ls -i "errno.h" -m "^E" -s - ${xflag}
}


if [ "${ELAST}" = "yes" ]; then
	xflag=""
	(echo "#include <errno.h>"; errno_h) | ${CC} -E - | \
	sed -ne 's/^[ 	]*\([0123456789][0123456789]*\).*$/\1/p' | sort -n | tail -1
else
	errno_h
fi
