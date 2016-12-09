#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local cq = require"cqueues".new()
cq:close()
check(not pcall(cq.wrap, cq), "cqueue should not allow new threads when closed") -- previously would trigger a segfault, should now error

cq:close()
info("cq:close() was safely called a second time")

say"OK"
