#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

local dbg = require"_cqueues.debug"

local function checkconv(timeout)
	local ms = dbg.f2ms(timeout)
	info("%g -> %gms", timeout, ms)
	check(ms / 1000 >= timeout, "conversion lost time (%g > %dms)", timeout, ms)

	local ts = dbg.f2ts(timeout)
	info("%g -> { %d, %d }", timeout, ts.tv_sec, ts.tv_nsec)
	check(ts.tv_sec + (ts.tv_nsec * 1000000000) >= timeout, "conversion lost time (%g > { %d, %d })", timeout, ts.tv_sec, ts.tv_nsec)
end

local main = cqueues.new()

local function checksleep(timeout, noloop)
	local start, elapsed

	info("sleeping for %gs (noloop:%s)", timeout, noloop and "yes" or "no")

	if noloop then
		local start = cqueues.monotime()
		cqueues.poll(timeout)
		elapsed = cqueues.monotime() - start
	else
		check(main:wrap(function ()
			local start = cqueues.monotime()
			cqueues.poll(timeout)
			elapsed = cqueues.monotime() - start
		end):loop())
	end

	info("%gs elapsed", elapsed)
	check(elapsed >= timeout, "sleep too short (%g < %g)", elapsed, timeout)
end

for _, noloop in ipairs{ false, true } do
	for _, timeout in ipairs{ 0.1, 1e-4, 1e-5, 1e-10, 1e-11, 0.9999, 0.999999999, 0.9999999999, 0.9, 1.0, 1.1, 2.0 } do
		if not noloop then checkconv(timeout) end
		checksleep(timeout, noloop)
	end
end

local INT_MAX = dbg.INT_MAX

for _, timeout in ipairs{ INT_MAX + 1, INT_MAX * 2, INT_MAX + 0.9999 } do
	local ms, is_int_max = dbg.f2ms(timeout)
	info("%g -> %d", timeout, ms)
	check(is_int_max, "%g didn't clamp", timeout)
end

for _, timeout in ipairs{ 2^63 } do
	local ts, is_long_max = dbg.f2ts(timeout)
	info("%g -> { %g, %g }", timeout, ts.tv_sec, ts.tv_nsec)
	check(is_long_max, "%g didn't clamp", timeout)
end

say("OK")
