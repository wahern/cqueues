#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
--
-- Timeouts are stored as deadlines--absolute clock values of when we should
-- resume the thread. Also, timeouts are stored and computed in floating
-- point and converted to integers only when neeed. If the difference
-- between the nearest deadline and the current time is less than the
-- resolution of the system call timeout parameter (1 millisecond for
-- epoll_wait), truncation will cause us to compute a timeout value of 0.
-- The fix was to use ceil(3) to round up fractional seconds after shifting
-- but before integer conversion. Additionally, subnormal floating point
-- values are now also rounded up to the minimum resolution (e.g. 1
-- millisecond for epoll_wait, 1 nanosecond for kevent).
--
require"regress".export".*"

local cqueues = require"cqueues"

local cq = cqueues.new()

cq:wrap(function ()
	cqueues.sleep(0.1)
end)

local i = 0
while not cq:empty() do
	assert(cq:step())
	i = i + 1
end

check(i == 2, "loop waking up too early")

say("OK")

