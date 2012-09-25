#!/usr/local/lua52/bin/lua

local cqueues = require("cqueues")
local notify = require("cqueues.notify")
local path = ... or "/tmp"

local nfy = notify.opendir(path)

local function addall(name, ...)
	if name then
		nfy:add(name, notify.ALL)
		addall(...)
	end
end

addall(select(2, ...))


local cq = cqueues.new()

cq:wrap(function()
	while true do
		local changes, filename = nfy:get()
		print(filename)
	end
end)


while not cq:empty() do
	local okay, why = cq:step()

	if not okay then
		error("cqueue: " .. why)
	end
end

