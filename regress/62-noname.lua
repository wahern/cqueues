#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local fileresult = auxlib.fileresult

check(cqueues.new():wrap(function ()
	local so, ok, why, error

	so, why, error = fileresult(socket.connect("nothing.nothing", 80))

	if error == errno.EAGAIN then
		ok, why, error = fileresult(so:connect(10))
	end

	check(error ~= errno.ENOENT, "socket.connect shouldn't return ENOENT anymore")

	-- Until we can expose DNS_ENONAME, just check we didn't get a
	-- system error.
	check(not error or error < 0, why)
end):loop())

say"OK"
