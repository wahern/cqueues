#!/bin/sh
_=[[
	exec runlua "$0" "$@"
]]

local cqueues = require"cqueues"
local thread = require"cqueues.thread"
local auxlib = require"cqueues.auxlib"

local assert = auxlib.assert
local fileresult = auxlib.fileresult

assert(cqueues.new():wrap(function ()
	local thr = assert(thread.start(function ()
		local signal = require"cqueues.signal"
		local ffi  = require"ffi"

		ffi.cdef"void pthread_exit(void *);"

		io.stderr:write("calling pthread_exit\n")
		ffi.C.pthread_exit(nil)
		io.stderr:write("exited\n")
	end))

	local ok, why = auxlib.fileresult(thr:join(5))

	print(ok, why)
end):loop())

