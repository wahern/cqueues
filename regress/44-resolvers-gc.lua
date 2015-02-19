#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua -j- "$0" "$@"
]]

require"regress".export".*"

local resolvers = require"cqueues.dns.resolvers"

local function caughtleak()
	local pool = resolvers.stub()

	local gotleak

	pool:onleak(function () gotleak = true end)
	pool:get()

	for i=1,10 do
		collectgarbage"collect"
	end

	return gotleak
end

check(caughtleak(), "resolver leak not detected")

if jit then
	_VERSION = "Lua 5.2" -- pretend that we support __gc on tables
	check(not caughtleak(), "expected not to catch leak")
end

say("OK")
