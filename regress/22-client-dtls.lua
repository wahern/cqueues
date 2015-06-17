#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

require"regress".export".*"

local context = require"openssl.ssl.context"

local function exists(path)
	local fh = io.open(path, "r")

	if fh then
		fh:close()
		return true
	else
		return false
	end
end

-- return integer version of openssl(1) command-line tool at path
local function openssl_version(path)
	local fh = io.popen(string.format("%s version", path), "r")
	local ln = (fh and fh:read()) or ""

	if fh then
		fh:close()
	end

	local M, m, p = ln:match("(%d+)%.(%d+)%.(%d+)")

	if p then
		return (tonumber(M) * 268435456) + (tonumber(m) * 268435456) + (tonumber(p) * 4096)
	end
end

-- find most recent version of openssl(1) command-line tool
local function openssl_path()
	local paths = check(os.getenv"PATH", "no PATH in environment")
	local path = nil
	local version = 0

	for D in paths:gmatch("[^:]+") do
		local tmp_path = D .. "/openssl"
		local tmp_version = exists(tmp_path) and openssl_version(tmp_path)

		if tmp_version and tmp_version > version then
			info("found %s (%x)", tmp_path, tmp_version)
			path = tmp_path
			version = tmp_version
		end
	end

	return version > 0 and path
end

local function openssl_run(path)
	local key, crt = genkey()
	local tmpname = os.tmpname()
	local tmpfile = check(io.open(tmpname, "w"))

	check(tmpfile:write(key:toPEM"private"))
	check(tmpfile:write(tostring(crt)))
	check(tmpfile:flush())
	tmpfile:close()

	local thr, com = check(thread.start(function (com, path, tmpname)
		require"regress".export".*"

		-- utility will exit when stdin closes, so arrange for
		-- stdin to close when we exit
		local stdin_r, stdin_w = assert(socket.pair{ cloexec = false })
		local exec = string.format("exec %s s_server -dtls1 -key %s -cert %s <&%d %d<&-", path, tmpname, tmpname, stdin_r:pollfd(), stdin_w:pollfd())
		local fh = io.popen(exec, "r")

		info("executed `%s`", exec)

		fh:read() --> only care that it started up
		os.remove(tmpname)

		com:write"OK\n"

		for _ in fh:lines() do
			-- nothing
		end
	end, path, tmpname))

	local ok = check(com:read()) --> only care that it started up

	check(ok == "OK", "failed to run openssl command-line utility")
end

local main = cqueues.new()

assert(main:wrap(function ()
	-- spin up DTLS server using openssl(1) command-line utility
	openssl_run(check(openssl_path(), "no openssl command-line utility found"))

	-- create client socket
	local con = socket.connect{ host="localhost", port=4433, type=socket.SOCK_DGRAM };
	check(fileresult(con:starttls(context.new"DTLSv1", 3)))
end):loop())

say"OK"

