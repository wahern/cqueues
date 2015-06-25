#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local context = require"openssl.ssl.context"

local cq = cqueues.new()

socket.setmode("nb", "nb")

local A, B = check(fileresult(socket.pair()))

cq:wrap(function()
	local key, crt = genkey()
	local ctx = context.new("TLSv1", true)
	ctx:setCertificate(crt)
	ctx:setPrivateKey(key)

	check(fileresult(A:write("unsecure\n")))
	info"(S) initiating TLS handshake"
	A:starttls(ctx)
	info"(S) handshake complete"
	check(fileresult(A:write("secure\n")))
end)

cq:wrap(function()
	check(check(fileresult(B:read())) == "unsecure")
	info"(C) initiating TLS handshake"
	check(fileresult(B:starttls()))
	info"(C) handshake complete"
	check(check(fileresult(B:read())) == "secure")
end)

local ok, err, errno, thd = cq:loop()
if not ok then
	print(debug.traceback(thd, err))
end
