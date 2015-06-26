#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local context = require"openssl.ssl.context"

local function starttls(autoflush, pushback)
	local cq = cqueues.new()
	local A, B = check(fileresult(socket.pair()))
	local cv = condition.new()
	local key, crt = genkey()
	local ctx = context.new("TLSv1", true)
	local text_unsecure = "unsecure"
	local text_secure = "secure"

	A:settimeout(2)
	B:settimeout(2)

	if autoflush then
		A:setmode(nil, "fba")
	else
		A:setmode(nil, "fbA")
	end

	if pushback then
		B:setmode("fbp", nil)
	else
		B:setmode("fbP", nil)
	end

	ctx:setCertificate(crt)
	ctx:setPrivateKey(key)

	info("test autoflush:%s pushback:%s", tostring(autoflush), tostring(pushback))

	cq:wrap(function()
		info("(A) sending %d bytes", #text_unsecure)
		check(fileresult(A:write(text_unsecure)))

		cv:signal()

		info"(A) initiating TLS handshake"
		local ok, why, error = fileresult(A:starttls())
		info("(A) starttls error: %d", error or 0)
		if pushback and autoflush then
			check(ok, "(A) pushback/autoflush test failed (%s)", why)
		else
			check(not ok, "(A) pushback/autoflush control test failed")
			return
		end

		info"(A) handshake complete"
		check(fileresult(A:write(text_secure)))
		check(fileresult(A:flush()))
	end)

	cq:wrap(function()
		check(fileresult(cv:wait()))

		info("(B) reading %d bytes", #text_unsecure)
		local text, why, error = fileresult(B:read(#text_unsecure))
		info("(B) read error: %d", error or 0)
		if autoflush then
			check(text == text_unsecure, "(B) autoflush test failed (%s)", text or why)
		else
			check(text ~= text_unsecure, "(B) autoflush control test failed")
			return
		end

		info"(B) initiating TLS handshake"
		local ok, why, error = fileresult(B:starttls(ctx))
		info("(B) starttls error: %d", error or 0)
		if pushback then
			check(ok, "(B) pushback test failed (%s)", why)
		else
			check(not ok, "(B) pushback control test failed")
			return
		end

		info"(B) handshake complete"
		check(check(fileresult(B:read(#text_secure))) == text_secure)
	end)

	check(cq:loop())
end

starttls(true, false)
starttls(false, true)
starttls(true, true)

say"OK"
