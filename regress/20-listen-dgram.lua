#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local main = cqueues.new()

main:wrap(function ()
	local con = socket.listen{ host = "127.0.0.1", port = 0, type = socket.SOCK_DGRAM }

	check(con:listen())
end)

check(main:loop())

say("OK")

