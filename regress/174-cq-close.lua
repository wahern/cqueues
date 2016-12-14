#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"


local mainloop = cqueues.new()
local cv = condition.new()
local cq = cqueues.new()

local closed = false
local polling, polled = false, false
local tests = 0
local okays = 0

local function test(...)
	tests = tests + 1
	mainloop:wrap(function (f, ...)
		f(...)
		okays = okays + 1
	end, ...)
end

test(function ()
	local function checkresult(ready)
		info"awoke on controller readiness"
		polling = false
		polled = true

		check(closed == true, "spurious wakeup")
		check(ready == cq, "cqueue not cancelled")
		check(cqueues.type(cq), "cqueue not closed")
	end

	cv:signal()
	polling = true
	info"polling controller"
	checkresult(cqueues.poll(cq, 3))
end)

test(function ()
	check(not polled, "polling thread unexpectedly finished")
	if not polling then
		info"waiting on polling thread"
		cv:wait(5)
		check(polling, "expected polling thread")
	end

	closed = true
	info"closing controller"
	cq:close()
	check(not pcall(cq.wrap, cq), "cqueue should not allow new threads when closed") -- previously would trigger a segfault, should now error

	info"closing controller again"
	cq:close()
	info("cq:close() was safely called a second time")
end)

ok, why = mainloop:loop()
check(ok, "%s", why)
check(tests == okays, "expected %d okays, got %d", tests, okays)

say"OK"
