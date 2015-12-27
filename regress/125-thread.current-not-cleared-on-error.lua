#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local cq = cqueues.new()
local is_ok = false
cq:wrap(function()
    cq:wrap(function()
        is_ok = true
    end)
    error("an error", 0)
end)

-- First step should signal an error
local ok, err = cq:step()
check(not ok and err == "an error", err)

-- Second step should succeed
check(cq:step())
check(is_ok, "second thread not run")
say("OK")
