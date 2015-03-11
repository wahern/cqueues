#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua -t -j- "$0" "$@"
]]

require"regress".export".*"

check(jit, "LuaJIT required")
check(errno.EOWNERDEAD, "EOWNERDEAD not defined")

local thr = assert(thread.start(function ()
	local errno = require"cqueues.errno"
	local ffi  = require"ffi"

	require"regress".export".*"

	debug"calling prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)"

	local PR_SET_SECCOMP = 22
	local SECCOMP_MODE_STRICT = 1
	ffi.cdef"int prctl(int, unsigned long, unsigned long, unsigned long, unsigned long)"
	local ok, rv = pcall(ffi.C.prctl, PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0)

	if not ok then
		debug("prctl call failed: %s", rv)
	elseif rv ~= 0 then
		debug("prctl call failed: %s", errno.strerror(ffi.errno()))
	else
		debug"attempting to open /nonexistant"
		io.open"/nonexistant" -- should cause us to be killed
		debug"prctl call failed: still able to open files"
	end

	debug"calling pthread_exit"

	ffi.cdef"void pthread_exit(void *);"
	ffi.C.pthread_exit(nil)

	debug"pthread_exit call failed: thread still running"
end))

local ok, why, code = auxlib.fileresult(thr:join(5))

check(not ok, "thread unexpectedly joined (%s)", why or "no error")
check(code == errno.EOWNERDEAD or code == errno.ETIMEDOUT, "unexpected error: %s", why)
check(code == errno.EOWNERDEAD, "robust mutex strategy not supported on this system")

say"OK"
