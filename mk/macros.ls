#!/bin/sh
#
# List specified macros
#

set -e

: ${CC:=cc}
: ${CPPFLAGS:=}
: ${MACRO:=.}
: ${VENDOR:=}
: ${INCLUDE:=}
: ${TMPFILE:=.$(basename $0).c}
: ${PREPEND:=}
: ${EXPAND:=no}

NL="
"

usage() {
	cat <<-EOF
	usage: $(basename $0) -m:v:i:t:xh
	  -i INCLUDE  include file (e.g. <errno.h>)
	  -m REGEX    regular expression macro name filter
	  -s PATH     path to supplemental list, one per line
	  -t TMPFILE  compiler intermediate tmp file
	  -v VENDOR   compiler vendor name (e.g. gcc, clang, sunpro)
	  -x          expand macros
	  -h          print this usage message

	Report bugs to <william@25thandClement.com>
	EOF
}

while getopts i:m:s:t:v:xh OPT; do
	case "${OPT}" in
	i)
		case "${OPTARG}" in
		\<*)
			INCLUDE="${INCLUDE}#include ${OPTARG}${NL}"
			;;
		\"*)
			INCLUDE="${INCLUDE}#include ${OPTARG}${NL}"
			;;
		*)
			INCLUDE="${INCLUDE}#include <${OPTARG}>${NL}"
			;;
		esac
		;;
	m)
		MACRO="${OPTARG}"
		;;
	s)
		PREPEND="${OPTARG}"
		;;
	t)
		TMPFILE="${OPTARG}"
		;;
	v)
		VENDOR="${OPTARG}"
		;;
	x)
		EXPAND=yes
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


vendor() {
	SCRIPT="$(dirname $0)/vendor.cc"

	if [ -n "${SCRIPT}" -a -x "${SCRIPT}" ]; then
		env CC="${CC}" ${SCRIPT}
	else
		${CC} -E - <<-EOF | awk '/sunpro/||/clang/||/gcc/||/other/{ print $1; exit; }'
			#if defined __SUNPRO_C
			sunpro
			#elif defined __clang__
			clang
			#elif defined __GNUC__
			gcc
			#else
			other
			#endif
		EOF
	fi
}


filter() {
	awk "\$1~/^#define/ && \$2~/${MACRO}/{ print \$2 }"
}


macros() {
	if [ -n "${PREPEND}" ]; then
		cat "${PREPEND}"
	fi

	case "${VENDOR:-$(vendor)}" in
	*sunpro*)
		trap "rm -f ${TMPFILE}" EXIT
		echo "${INCLUDE}" >| ${TMPFILE}
		${CC} ${CPPFLAGS} -xM ${TMPFILE} | awk '/\.h$/{ print $2 }' | sort -u | xargs cat | filter
		rm ${TMPFILE}
		;;
	*)
		echo "${INCLUDE}" | ${CC} ${CPPFLAGS} -dM -E - | filter
		;;
	esac
}

expand() {
	if [ "${EXPAND}" = "yes" ]; then
		(echo "${INCLUDE}"; awk '{ print "\"<<<< "$1" >>>>\" "$1 }') | ${CC} ${CPPFLAGS} -E - | awk '$1~/^"<<<</{ print $2""substr($0, index($0, ">>>>") + 5) }'
	else
		cat
	fi
}

macros | sort -u | expand
