#!/bin/sh
#
# List all EXXXX macros
#

set -e 

: ${CC:=cc}

TMPFILE=".$(basename $0).c"
trap "rm -f ${TMPFILE}" EXIT

compiler() {
	${CC} -E - <<-EOF | grep -v \#
		#if defined __SUNPRO_C
		sunpro
		#elif defined __clang__
		clang
		#elif defined __GNUC__
		gcc
		#else
		unknown
		#endif
	EOF
}

filter() {
	awk '$1~/^#define/ && $2~/^E/{ print $2 }' | sort -u
}

case "$(compiler)" in
	*sunpro*)
		echo "#include <errno.h>" >| ${TMPFILE}
		${CC} -xM .tmp.c | awk '/\.h$/{ print $2 }' | sort -u | xargs cat | filter
		rm ${TMPFILE}
		;;
	*)
		echo "#include <errno.h>" | ${CC} -dM -E - | filter
		;;
esac
