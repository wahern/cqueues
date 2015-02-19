#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua -j- "$0" "$@"
]]

require"regress".export".*"

check(jit, "LuaJIT required")
check(errno.EOWNERDEAD, "EOWNERDEAD not defined")

local thr = assert(thread.start(function ()
	local signal = require"cqueues.signal"
	local ffi  = require"ffi"

	ffi.cdef"void pthread_exit(void *);"

	ffi.C.pthread_exit(nil)
end))

local ok, why, code = auxlib.fileresult(thr:join(5))

check(not ok, "thread unexpectedly joined cleanly")
check(code == errno.EOWNERDEAD or code == errno.ETIMEDOUT, "unexpected error: %s", why)
check(code == errno.EOWNERDEAD, "robust mutex strategy not supported on this system")

say"OK"
