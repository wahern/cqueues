#!/usr/bin/env lua

local cqueues = require"cqueues"
local resolver = require"cqueues.dns.resolver"

local name, type = ...

assert(cqueues.new():wrap(function()
	local res = resolver.stub()

	print(tostring(assert(res:query(name or "google.com", type or "A"))))
end):loop())

