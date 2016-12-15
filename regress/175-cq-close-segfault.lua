#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local cq = cqueues.new()
local ok, why = cq:wrap(function ()
	cq:close()
end):loop()
check(not ok, "expected loop to fail")
check(tostring(why):find"cqueue running", "unexpected error (%s)", tostring(why))

say"OK"
