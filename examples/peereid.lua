#!/usr/bin/env lua

local cqueues = require"cqueues"
local socket = require"cqueues.socket"

local path = "./peereid.sock"

local unix = socket.listen{ path = path, unlink = true }
local loop = cqueues.new()

loop:wrap(function()
	local con = unix:accept()
	local pid, uid, gid = con:peerpid(), con:peereid()

	print(string.format("pid:%s uid:%s gid:%s", pid, uid, gid))
end)

loop:wrap(function()
	local con = socket.connect{ path = path }

	con:connect()
end)

-- make sure we delete the socket
local ok, why = loop:loop()
os.remove(path)
assert(ok, why)
