#!/bin/sh
set -e # strict error
set -f # disable pathname expansion
set -C # noclobber
unset IFS

SRCDIR="$(cd "${0%%/*}/.." && pwd -L)"
PATH="${PATH:-$(command -p getconf PATH)}:${SRCDIR}/mk"

lua51path="${SRCDIR}/regress/.local/share/5.1"
lua51cpath="${SRCDIR}/regress/.local/lib/5.1"
lua52path="${SRCDIR}/regress/.local/share/5.2"
lua52cpath="${SRCDIR}/regress/.local/lib/5.2"
lua53path="${SRCDIR}/regress/.local/share/5.3"
lua53cpath="${SRCDIR}/regress/.local/lib/5.3"

export LUA_PATH="${lua51path}/?.lua;${SRCDIR}/regress/?.lua;;"
export LUA_CPATH="${lua51cpath}/?.so;;"
export LUA_PATH_5_2="${lua52path}/?.lua;${SRCDIR}/regress/?.lua;;"
export LUA_CPATH_5_2="${lua52cpath}/?.so;;"
export LUA_PATH_5_3="${lua53path}/?.lua;${SRCDIR}/regress/?.lua;;"
export LUA_CPATH_5_3="${lua53cpath}/?.so;;"

(cd "${SRCDIR}" && make -s install \
	lua51path="${lua51path}" lua51cpath="${lua51cpath}" \
	lua52path="${lua52path}" lua52cpath="${lua52cpath}" \
	lua53path="${lua53path}" lua53cpath="${lua53cpath}")

if [ ! -d "${SRCDIR}/regress/.local/lib/5.3" ]; then
	export RUNLUA_R="${RUNLUA_R:=5.1-5.2}"
fi

export PROGNAME="${0##*/}"
