#!/usr/bin/env lua

local cqueues = require"cqueues"
local resolver = require"cqueues.dns.resolver"
local packet = require"cqueues.dns.packet"
local record = require"cqueues.dns.record"

local name, type = ...

assert(cqueues.new():wrap(function()
	local res = resolver.stub()

	print(tostring(assert(res:query(name or "google.com", type or "A"))))
end):loop())

