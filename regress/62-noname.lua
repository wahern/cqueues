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
	info("socket.connect -> %s error:%d (%s)", tostring(so), error or 0, tostring(why))
	check(so, "failed to create socket: %s", tostring(why))

	so:onerror(function (so, op, why, lvl) return why end)

	ok, why, error = fileresult(so:connect(10))
	info("socket:connect -> %s error:%d (%s)", tostring(ok), error or 0, tostring(why))
	check(not ok and error and error ~= 0, "socket:connect shouldn't have succeeded")
	check(error ~= errno.ENOENT, "socket:connect shouldn't return ENOENT anymore")
	check(error < 0, "socket:connect should have returned DNS_ENONAME but got %d (%s)", error, tostring(why))
end):loop())

say"OK"
