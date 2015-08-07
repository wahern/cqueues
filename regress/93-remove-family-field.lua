#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

--
-- Simple test to check whether we broke initializing a socket object with a
-- pipe descriptor.
--
info"creating FILE handle attached to printf invocation"
local fh = check(io.popen("printf 'OK\\n'", "r"))

info"creating socket object attached to pipe (via FILE handle)"
local con = check(fileresult(socket.dup(fh)))

info"reading printed string from pipe"
local what = check(fileresult(con:read"*l"))

check(what == "OK", "expected 'OK' but got '%q'", what)

say("OK")
