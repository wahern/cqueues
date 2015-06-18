#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

--
-- lso_fill attempts to read more than requested, and returns EAGAIN even if
-- it fulfilled the request completely. socket:fill is the only API method
-- which triggers this bug because all the others do speculative reads and
-- test if the input buffer contains sufficient data to fulfill the request.
-- Only if it doesn't do they read or return the error from lso_fill.
-- socket:fill, however, unconditionally returns the error from lso_fill,
-- regardless if the input buffer contains the requested amount of data
-- after lso_fill returns.
--
check(cqueues.new():wrap(function ()
	local a, b = check(socket.pair())

	local send = "test"

	info('writing "%s" (%d bytes)', send, #send)
	check(a:write(send))
	a:flush()
	local n = a:stat().sent.count
	check(n == #send, "only %d bytes flushed", n)

	info("filling %d bytes", #send)
	check(b:fill(#send))
	info("%d bytes pending", (b:pending()))

	info("reading %d bytes", #send)
	local rcvd = check(b:read(4))
	check(send == rcvd, "data doesn't match (send \"%s\" but got \"%s\")", send, rcvd)
end):loop())

say"OK"
