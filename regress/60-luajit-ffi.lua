#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local monotime = cqueues.monotime
local ctr = 0
local begin = monotime()

for i=1,math.pow(2, 24) do
	ctr = ctr + monotime()
end

print(ctr, monotime() - begin)
os.exit()
