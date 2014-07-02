#!/usr/bin/env lua

local cqueues = require"cqueues"
local promise = require"cqueues.promise"
local resolver = require"cqueues.dns.resolver"
local auxlib = require"cqueues.auxlib"

local host, type = ...

assert(cqueues.new():wrap(function ()
	-- use fully recursive resolver to make sure it takes awhile
	local pkt = promise.new(function (host, type)
		return resolver.root():query(host, type)
	end, host or "parliament.uk", type or "MX")

	print(auxlib.tostring(pkt))
end):loop())
