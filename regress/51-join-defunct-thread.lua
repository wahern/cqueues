#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua -t -j- "$0" "$@"
]]

require"regress".export".*"

check(jit, "LuaJIT required")
check(errno.EOWNERDEAD, "EOWNERDEAD not defined")

local thr, con = assert(thread.start(function (con)
	local errno = require"cqueues.errno"
	local ffi  = require"ffi"

	require"regress".export".*"

	--
	-- NOTE: On musl-libc the parent process deadlocks on flockfile as
	-- apparently the thread dies when writing to stderr. Log to our
	-- communications socket instead, which doesn't hold any locks.
	--
	local function info(...)
		con:write(string.format(...), "\n")
		con:flush()
	end

	info"calling prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)"

	local PR_SET_SECCOMP = 22
	local SECCOMP_MODE_STRICT = 1
	ffi.cdef"int prctl(int, unsigned long, unsigned long, unsigned long, unsigned long)"
	local ok, rv = pcall(function () return ffi.C.prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) end)

	if not ok then
		local rv = string.match(rv, "[^:]+:[^:]+$") or rv
		info("prctl call failed: %s", rv)
	elseif rv ~= 0 then
		info("prctl call failed: %s", errno.strerror(ffi.errno()))
	else
		info"attempting to open /nonexistant"
		io.open"/nonexistant" -- should cause us to be killed
		info"prctl call failed: still able to open files"
	end

	info"calling pthread_exit"

	ffi.cdef"void pthread_exit(void *);"
	ffi.C.pthread_exit(nil)

	info"pthread_exit call failed: thread still running"
end))

local main = check(cqueues.new())

-- read thread's log lines from pcall because socket:read will throw an
-- error when the socket is closed asynchronously below.
check(main:wrap(pcall, function ()
	for ln in con:lines() do
		info("%s", ln)
	end
end))

check(main:wrap(function ()
	local ok, why, code = auxlib.fileresult(thr:join(5))

	check(not ok, "thread unexpectedly joined (%s)", why or "no error")
	check(code == errno.EOWNERDEAD or code == errno.ETIMEDOUT, "unexpected error: %s", why)
	check(code == errno.EOWNERDEAD, "robust mutex strategy not supported on this system")

	con:close()
end))

check(main:loop())

say"OK"
