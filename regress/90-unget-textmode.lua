#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local function test_with_mode(str, mode)
	local c, s = socket.pair()
	check(s:xwrite(str, "bn"))
	local foo = c:xread(-99999, mode)
	check(c:unget(foo, mode))
	local bar = c:xread(-99999, mode)
	check(foo == bar, "unget + read does not round trip")
end
local function test(str)
	info("testing: %q", str)
	test_with_mode(str, "t")
	test_with_mode(str, "b")
end

test'test'
test'test\n'
test'hi\r\nthere\nworld\r'
test'\n\n'
test'foo\r\r\n'

say("OK")
