#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local function uname()
	return check(check(io.popen("uname -a", "r")):read"*a")
end

local function localpath(s)
	local family, pathname = check(fileresult(s:localname()))

	check(family == socket.AF_UNIX, "wrong address family (%s)", tostring(family))

	return pathname
end

info"creating socket pair"
local a, b = check(socket.pair(socket.AF_UNIX))

info"check that pathname is nil"
check(localpath(a) == nil, "pathname of AF_UNIX socket pair not nil (%q)", localpath(a))
a:close()
b:close()

if uname():find"Linux" then
	local pathname = "\00082-localname-garbage.sock"

	info("creating abstract socket at %q", pathname)

	local srv = check(socket.listen{ path = pathname })
	local a, b

	info("checking for abstract socket pathname")
	check(localpath(srv) == pathname, "bad pathname (%q)", localpath(srv))

	local main = cqueues.new()

	main:wrap(function ()
		info("accepting connection at %q", pathname)
		a = check(srv:accept())
	end)

	main:wrap(function ()
		info("connecting to %q", pathname)
		b = check(socket.connect{ path = pathname })
	end)

	check(main:loop())

	check(localpath(a) == pathname, "pathname of connected AF_UNIX socket wrong (%q)", localpath(a))
	check(localpath(b) == nil, "pathname of connected AF_UNIX socket not nil (%q)", localpath(b))
end

say("OK")

