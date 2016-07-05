#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local main = cqueues.new()

collectgarbage "stop"

assert(main:wrap(function()
	local pool = dns.getpool()
	for _=1, pool.hiwat + 1 do
		check(pool:query("google.com", 'AAAA', 'IN', 1))
	end
end):loop())

say"OK"
