#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
--
-- Issue #194 -- AF_UNIX can't bind source and destination
--
require"regress".export".*"

assert(socket.connect {
	path = "foo";
	bind = {path="bar"};
})

say("OK")

