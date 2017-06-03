#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local cq = cqueues.new()
local rd, wr = check(socket.pair())
local pre_poll = false
local post_poll = false
cq:wrap(function()
	pre_poll = true
	cqueues.poll({
		pollfd = rd:pollfd();
		events = "r";
	})
	post_poll = true
end)
assert(cq:step(0))
check(pre_poll and not post_poll)

local r, w, p = cq:pollset()
check(r.n == 1 and r[2] == rd:pollfd(), "read set doesn't contain expected values")
check(w.n == 0, "write set doesn't contain expected values")
check(p.n == 0, "priority set doesn't contain expected values")

assert(cq:step(0))
check(not post_poll, "Thread was unexpectedly advanced")

cqueues.cancel(rd)
assert(cq:step(0))

check(post_poll, "Thread wasn't advanced")

say("OK")
