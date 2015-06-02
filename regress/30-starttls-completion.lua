#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

require"regress".export".*"

local so = socket.connect("google.com", 443)
local ok, why = auxlib.fileresult(so:starttls())
check(ok, "STARTTLS failed: %s", why)
local ssl = check(so:checktls(), "no SSL object")
local crt = ssl:getPeerCertificate()
check(crt ~= nil, "bug not fixed")
say("OK")
