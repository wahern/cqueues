#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
--
-- Simple test of controller alerts to check whether our eventfd support
-- works and didn't break anything else. A controller triggers its alert
-- event when adding a new coroutine and it's not currently looping.
--
require"regress".export".*"

local main = cqueues.new()
local sub = cqueues.new()
local sub_islooping = false
local sub_alerted = false

assert(main:wrap(function()
	sub_islooping = true
	assert(sub:loop())
end))

assert(main:step(0))
assert(sub_islooping)

assert(main:wrap(function ()
	assert(not sub_alerted)

	-- this should cause the main loop to resume the sub loop
	assert(sub:wrap(function()
		sub_alerted = true
	end))
end))

assert(main:loop(3))
check(sub_alerted, "sub loop never woke up")

say"OK"
