#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

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

