#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local main = cqueues.new()

local _cache = {}
local function megarep(s)
	if not _cache[s] then
		_cache[s] = string.rep(string.rep(s, 1024), 1024)
	end

	return _cache[s]
end

local function test(bufsiz)
	local loop = cqueues.new()

	local rd, wr = check(socket.pair())

	wr:setvbuf("full", bufsiz)

	local sem = { count = 0, condvar = condition.new() }

	local function sem_get()
		while sem.count < 1 do
			sem.condvar:wait()
		end

		sem.count = sem.count - 1
		sem.condvar:signal()
		cqueues.sleep(0)
	end

	local function sem_put(n)
		sem.count = sem.count + (n or 1)
		sem.condvar:signal()
		cqueues.sleep(0)
	end

	for i=0,3 do
		loop:wrap(function ()
			sem_get()

			local ch = string.char(string.byte"A" + i)

			for i=1,10 do
				check(wr:write(megarep(ch)))
			end

			check(wr:flush())

			sem_put()
		end)
	end

	loop:wrap(function ()
		sem_put(4)

		repeat
			sem.condvar:wait()
		until sem.count == 4

		wr:shutdown"rw"
	end)

	local interleaved = false

	loop:wrap(function ()
		for buf in rd:lines(1024 * 1024) do
			local ch = string.sub(buf, 1, 1)
			local uniform = not buf:match(string.format("[^%s]", ch))

			interleaved = interleaved or not uniform

			info("read %d bytes (interleaved:%s)", #buf, not uniform)
		end
	end)

	check(loop:loop())

	return interleaved
end

info"begin control test"
check(test(4096) == true, "expected control test to interleave")
info"control test OK"

info"begin test case"
check(test(-1) == false, "test case interleaved")
info"test case OK"

say("OK")
