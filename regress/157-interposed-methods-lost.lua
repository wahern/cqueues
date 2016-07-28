#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
-- load dns.config first so that subsequent loads of DNS modules overwrite
-- the config metatable
local config = require"cqueues.dns.config"
local resolver = require"cqueues.dns.resolver" -- ensure config mt reloaded
require"regress".export".*"

-- config.new would fail because the :set method it depended upon is an
-- interposed Lua function added to the userdata metatable. When subsequent
-- modules which depended on the metatable definition were loaded, they
-- called dnsL_loadall. dnsL_loadall defined all the internal metatables,
-- which since commit 4d66661 had the effect of replacing any pre-existing
-- __index field with a new table containing only the original C-defined
-- methods. Previously cqs_newmetatable short-circuited when a metatable
-- existed. The purpose of 4d66661 was to permit forced reloading of all Lua
-- modules by clearing package.loaded; the original behavior resulted in
-- modules interposing the same functions multiple times.
info"creating resolver config object"
local cfg = config.new{
	nameserver = { "1.2.3.4" },
	lookup = { "file", "bind", "cache" },
	options = { edns0 = true },
}

info("resolv.conf:")
for ln in tostring(cfg):gmatch("[^\n]+") do
	info("  %s", ln)
end

say"OK"
