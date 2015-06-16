#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

require"regress".export".*"

local context = require"openssl.ssl.context"

local main = cqueues.new()

assert(main:wrap(function ()
	local so = socket.connect{ host="localhost", port=4433, type=socket.SOCK_DGRAM };
	assert(auxlib.fileresult(so:starttls(context.new"DTLSv1", 3)))
end):loop())

say"OK"

