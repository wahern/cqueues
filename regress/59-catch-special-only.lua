#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

require"regress".export".*"

local cq = cqueues.new()

local MAXSTACK = 1000000 + 10

local co = coroutine.create(function(...)
	cq:wrap(function (...)
		for i=1,MAXSTACK do
			if 0 == i % math.floor(MAXSTACK / 100) then
				info("%d", i)
			end
			cqueues.poll(0)
			local n = coroutine.yield(i)
			check(n == i + 1)
		end
	end, ...)

	local ok, why, errno, thr = cq:loop()

	if not ok then
		io.stderr:write(debug.traceback(thr))
		check(false)
	end
	
	return "done"
end)

for i=1,MAXSTACK do
	local ok, j = coroutine.resume(co, i)
	check(i == j)
end

check("done" == select(2, coroutine.resume(co, MAXSTACK + 1)))
check(coroutine.status(co) == "dead")

say("OK")