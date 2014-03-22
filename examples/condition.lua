#!/usr/bin/env lua
--
-- Test for inter-controller signaling. If it works, the inner loops should
-- terminate as soon as we signal the condition variable. Otherwise, they
-- shouldn't terminate till each timeouts in turn.
--
local cqueues = require"cqueues"
local cond = require"cqueues.condition"
local sleep = cqueues.sleep
local monotime = cqueues.monotime

local loop = cqueues.new()
local cv = cond.new()

local function printf(...) print(string.format(...)) end

local success = true

for i=1,5 do
	loop:wrap(function()
		local loop = cqueues.new()

		loop:wrap(function()
			local began = monotime()
			local okay = cv:wait(3)

			if not okay then
				success = false
			end

			printf("thread %d woke in %.1fs: %s", i, monotime() - began, (okay and "OK") or "FAIL")
		end)

		assert(loop:loop())
	end)
end


loop:wrap(function()
	print"sleeping..."
	sleep(2)
	print"signaling..."
	cv:signal()
end)

assert(loop:loop())

print((success and "OK") or "FAIL")
