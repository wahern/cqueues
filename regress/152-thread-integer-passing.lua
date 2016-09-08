#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua -r5.3- "$0" "$@"
]]
require"regress".export".*"

local function runtest(testf, ...)
	-- check that the test runs locally
	info("running test in main thread")
	local err = packerror(testf(...))
	if err then
		return nil, err:unpack()
	end

	-- check test when running from a thread
	info("running test in separate thread")
	local err, thr = packerror(thread.start(function (_, testf, ...)
		require"regress".export".*"

		testf = check(load(testf))
		local err = packerror(testf(...))
		check(not err, "%s", tostring(err))
	end, string.dump(testf), ...))
	if err then
		return nil, err:unpack()
	end

	local function joinresult(ok, ...)
		if not ok then
			return nil, ...
		elseif (...) then
			return fileresult(nil, ...)
		else
			return true
		end
	end

	return joinresult(fileresult(thr:join(5)))
end

local function checktest(...)
	local err = packerror(runtest(...))
	check(not err, "%s", tostring(err)) 
	return true
end

--
-- Assuming (among other things) ones' complement, two's complement, or
-- sign-and-magnitude (the only 3 possibilities permissible in a C
-- environment) and that lua_Integer has more value bits than lua_Number
-- has significand bits, then math.maxinteger shouldn't be representable
-- as a lua_Number.
--
do
	local function tofloat(i)
		check("integer" == math.type(i), "number not an integer (%s)", tostring(i))
		local n = i + 0.0
		check("float" == math.type(n), "number not a float (given %s, got %s)", tostring(i), tostring(n))
		return n
	end

	check(math.maxinteger ~= tofloat(math.maxinteger), "math.maxinteger unexpectedly representable as a float")

	local function test(i, n)
		if not thread.self() then
			info("checking integer (%s) and float (%s) equivalence", tostring(i), tostring(n))
		end

		check(i == math.maxinteger, "integer argument does not equal math.maxinteger (%s, %s)", tostring(i), tostring(math.maxinteger))
		check(i ~= n, "integer argument unexpectedly equals floating point argument (%s, %s)", tostring(i), tostring(n))

		return true
	end

	checktest(test, math.maxinteger, tofloat(math.maxinteger))
end

--
-- Check that we didn't break floating point in other odd ways.
--
do
	local function ftoa(n)
		return string.format("%a", n)
	end

	local function test(...)
		local t = pack(...)

		local function ftoa(n)
			return string.format("%a", n)
		end

		for i=1,t.n,2 do
			local n = t[i]
			local s = t[i + 1]

			if not thread.self() then
				info("checking float (%s) and string (%s)", tostring(n), tostring(s))
			end

			check(ftoa(n) == s, "floating point test failed (%s, %q)", tostring(n), tostring(s))
			check(tonumber(s) == n or math.abs(n) == math.huge, "floating point test failed (%s, %q)", tostring(n), tostring(s))
		end

		return true
	end

	checktest(test, 1.1, ftoa(1.1), 1/3, ftoa(1/3), math.huge, ftoa(math.huge), -math.huge, ftoa(-math.huge))
end

say"OK"
