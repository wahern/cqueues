#!/usr/local/lua52/bin/lua

local cqueues = require("cqueues")
local notify = require("cqueues.notify")
local path = ... or "/tmp"


--
-- list kernel capabilities
--
-- local f = {}
--
-- for flag in notify.flags(notify.FEATURES) do
-- 	f[#f + 1] = notify[flag]
-- end
--
-- io.stderr:write("using ", table.concat(f, ", "), "\n")


--
-- initialize our directory notifier
--
local nfy = notify.opendir(path, notify.ALL)

local function addall(name, ...)
	if name then
		nfy:add(name, notify.ALL)
		addall(...)
	end
end

addall(select(2, ...))


--
-- create controller and loop over file change notifications
--
local cq = cqueues.new()

cq:wrap(function()
	for flags, name in nfy:changes() do
		for flag in notify.flags(flags) do
			print(name, notify[flag])
		end
	end
end)


while not cq:empty() do
	local okay, why = cq:step()

	if not okay then
		error("cqueue: " .. why)
	end
end

