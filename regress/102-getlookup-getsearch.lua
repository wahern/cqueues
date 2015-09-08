#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local config = require"cqueues.dns.config"
local txt = io.tmpfile()

assert(txt:write([[
	search google.com yahoo.com wikipedia.org
	nameserver 8.8.8.8
]]))

local resconf = config.new()
resconf:loadfile(txt)

for i,dn in ipairs(resconf:getsearch()) do
	info("search[%d]: %s", i, dn)
end

for i,how in ipairs(resconf:getlookup()) do
	info("lookup[%d]: %s", i, dn)
end

say("OK")
