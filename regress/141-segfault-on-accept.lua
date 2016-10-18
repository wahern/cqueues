#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
--
-- Issue #141 -- Lua/C accept method binding doesn't check whether the
-- socket has already been closed, passing a NULL socket object to low-level
-- so_accept routine. Fix was to use the lso_checkself utility routine like
-- every other method, which will throw an error when passed a closed
-- socket.
--
require"regress".export".*"

info"opening listening socket"
local con = socket.listen("localhost", 0)

info"calling close"
con:close();

-- bug caused NULL dereference in so_clear, invoked from lso_accept
info"calling accept"
local ok = pcall(con.accept, con, 0);
check(not ok, "con:accept didn't throw error as expected")

say("OK")

