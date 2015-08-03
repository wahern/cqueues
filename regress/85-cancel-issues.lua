#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

--
-- Run our test. We don't have a way to force failure with versions of the
-- openssl module that have been fixed.
--
local main = check(cqueues.new())
local a, b = check(socket.pair(socket.SOCK_STREAM))
local cv = check(condition.new())

check(main:wrap(function ()
	local subloop = check(cqueues.new())

	subloop:wrap(function ()
		local event = { pollfd = a:pollfd(), events = "rp" }

		check(cv:signal())
		info"subloop: entering poll state"
		local ready, errmsg = fileresult(cqueues.poll(event))
		info"subloop: awoke from poll"

		check(ready or not errmsg, "subloop: poll error (%s)", tostring(errmsg))
		check(ready == event, "subloop: cancelled event did not poll ready")

		cv:signal()
	end)

	check(subloop:loop())
end))

check(main:wrap(function ()
	info"main loop: waiting on subloop to poll"
	cv:wait()
	info"main loop: cancelling socket"
	cqueues.cancel(a)
	info"main loop: waiting on subloop signal"
	check(cv:wait(3), "main loop: timeout before cancelled event polled ready")
end))

check(main:loop())

say"OK"
