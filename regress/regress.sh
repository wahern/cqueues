#!/bin/sh
set -e # strict error
set -f # disable pathname expansion
set -C # noclobber
unset IFS

: ${CQUEUES_SRCDIR:="$(cd "${0%%/*}/.." && pwd -L)"}
PATH="${PATH:-$(command -p getconf PATH)}:${CQUEUES_SRCDIR}/mk"

: ${REGRESS_VERBOSE:=1}
: ${REGRESS_REBUILD:=1}
: ${REGRESS_PROGNAME:=${0##*/}}
REGRESS_PROGNAME="${REGRESS_PROGNAME%.lua}"

export CQUEUES_SRCDIR REGRESS_VERBOSE REGRESS_REBUILD REGRESS_PROGNAME

SHORTOPTS="Br:j:Jqvh"

usage() {
	cat <<-EOF
	Usage: ${0##*/} [-${SHORTOPTS}]
	  -B        do not try to rebuild modules
	  -r RANGE  run specific Lua version
	  -j RANGE  run specific LuaJIT version
	  -J        exclude LuaJIT from candidate interpreters
	  -q        do not emit informational messages
	  -v        emit verbose informational messages
	  -h        print this usage message

	Report bugs to <william@25thandClement.com>
	EOF
}

while getopts "${SHORTOPTS}" OPTC; do
	case "${OPTC}" in
	B)
		REGRESS_REBUILD=0
		;;
	r)
		export RUNLUA_R="${OPTARG}"
		;;
	j)
		export RUNLUA_J="${OPTARG}"
		;;
	J)
		export RUNLUA_J="0-0"
		;;
	q)
		REGRESS_VERBOSE=0
		;;
	v)
		REGRESS_VERBOSE=2
		;;
	h)
		usage
		exit 0
		;;
	?)
		usage >&2
		exit 1
		;;
	esac
done

shift $((${OPTIND} - 1))

lua51path="${CQUEUES_SRCDIR}/regress/.local/share/5.1"
lua51cpath="${CQUEUES_SRCDIR}/regress/.local/lib/5.1"
lua52path="${CQUEUES_SRCDIR}/regress/.local/share/5.2"
lua52cpath="${CQUEUES_SRCDIR}/regress/.local/lib/5.2"
lua53path="${CQUEUES_SRCDIR}/regress/.local/share/5.3"
lua53cpath="${CQUEUES_SRCDIR}/regress/.local/lib/5.3"

export LUA_PATH="${lua51path}/?.lua;${CQUEUES_SRCDIR}/regress/?.lua;${LUA_PATH:-;}"
export LUA_CPATH="${lua51cpath}/?.so;${LUA_CPATH:-;}"
export LUA_PATH_5_2="${lua52path}/?.lua;${CQUEUES_SRCDIR}/regress/?.lua;${LUA_PATH_5_2:-;}"
export LUA_CPATH_5_2="${lua52cpath}/?.so;${LUA_CPATH_5_2:-;}"
export LUA_PATH_5_3="${lua53path}/?.lua;${CQUEUES_SRCDIR}/regress/?.lua;${LUA_PATH_5_3:-;}"
export LUA_CPATH_5_3="${lua53cpath}/?.so;${LUA_CPATH_5_3:-;}"


if [ "${0##*/}" = "regress.sh" ]; then
	case "${1:-build}" in
	build)
		LUA_API="$(runlua -e "print(_VERSION:match'%d.%d')")"
		unset MAKEFLAGS
		(cd "${CQUEUES_SRCDIR}" && make -s "install${LUA_API}" \
			lua51path="${lua51path}" lua51cpath="${lua51cpath}" \
			lua52path="${lua52path}" lua52cpath="${lua52cpath}" \
			lua53path="${lua53path}" lua53cpath="${lua53cpath}")
		exit $?
		;;
	*)
		printf "%s: %s: unknown command\n" "${0##*/}" "${1:-\'\'}" >&2
		exit 1
		;;
	esac
else
	if [ ${REGRESS_REBUILD} -eq 1 ]; then
		export REGRESS_REBUILD=0 # disable for recursive invocations

		(cd "${CQUEUES_SRCDIR}" && make -s install \
			lua51path="${lua51path}" lua51cpath="${lua51cpath}" \
			lua52path="${lua52path}" lua52cpath="${lua52cpath}" \
			lua53path="${lua53path}" lua53cpath="${lua53cpath}")
	fi

	if [ ! -d "${CQUEUES_SRCDIR}/regress/.local/lib/5.3" ] || ! runlua -e 'require"_cqueues"' >>/dev/null 2>&1; then
		export RUNLUA_R="${RUNLUA_R:=5.1-5.2}"
	fi

	case "$(uname -s)" in
	OpenBSD)
		: ${RUNLUA_T:=1}
		export RUNLUA_T
		;;
	esac
fi
