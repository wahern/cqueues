#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local pool = dns.getpool()
local r = pool:get()
pool:put(r)
local q = pool:get()
check(r == q, "resolver not reused")

say"OK"
