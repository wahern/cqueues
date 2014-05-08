local loader = function(loader, ...)
	local core = require"_cqueues"
	local errno = require"_cqueues.errno"
	local yield = coroutine.yield
	local resume = coroutine.resume
	local monotime = core.monotime
	local running = core.running
	local strerror = errno.strerror

	local _POLL = {}

	function core.poll(...)
		local _, immediate = running()

		if immediate then
			return yield(...)
		else
			return yield(_POLL, ...)
		end
	end -- core.poll

	function core.sleep(timeout)
		core.poll(timeout)
	end -- core.sleep


	--
	-- Provide coroutine wrappers for multilevel coroutine management to
	-- allow I/O polling of coroutine-wrapped code. The code checks for
	-- a special value returned by our poll routine (above), and will
	-- propogate a yield on I/O. Everything else should behave as usual.
	--
	local function _resume(co, ok, arg1, ...)
		if ok and arg1 == _POLL then
			return core.resume(co, yield(_POLL, ...))
		else
			return ok, arg1, ...
		end
	end -- _resume

	function core.resume(co, ...)
		return _resume(co, resume(co, ...))
	end -- core.resume

	local function _wrap(co, ok, ...)
		if ok then
			return ...
		else
			error((...), 0)
		end
	end -- _wrap

	function core.wrap(f)
		local co = coroutine.create(f)

		return function(...)
			return _wrap(co, _resume(co, resume(co, ...))) 
		end
	end -- core.wrap


	--
	-- Many routines return only an integer error number, as errors like
	-- EAGAIN are very common, and constantly pushing a new string on
	-- the stack would be inefficient. Also, the failure mode for some
	-- routines will return multiple false/nil falses which precede the
	-- error number. This assert routine handles these cases.
	--
	local function findwhy(x, ...)
		if x then
			if type(x) == "number" then
				return strerror(x) or x
			else
				return tostring(x)
			end
		elseif select("#", ...) > 0 then
			return findwhy(...)
		else
			return
		end
	end

	function core.assert(x, ...)
		if x then
			return x, ...
		end

		return error(findwhy(...), 2)
	end -- core.assert


	--
	-- Wrappers for the low-level :step interface to make managing event
	-- loops slightly easier.
	--
	local step; step = core.interpose("step", function (self, timeout)
		if core.running() then
			core.poll(self, timeout)

			return step(self, 0.0)
		else
			return step(self, timeout)
		end
	end) -- core:step

	core.interpose("loop", function (self, timeout)
		local ok, why

		if timeout then
			local curtime = monotime()
			local deadline = curtime + timeout

			repeat
				ok, why = self:step(deadline - curtime)
				curtime = monotime()
			until not ok or deadline <= curtime or self:empty()
		else
			repeat
				ok, why = self:step()
			until not ok or self:empty()
		end

		return ok, why
	end) -- core:loop

	core.interpose("errors", function (self, timeout)
		if timeout then
			local deadline = monotime() + timeout

			return function ()
				local curtime = monotime()

				if curtime < deadline then
					local ok, why = self:loop(deadline - curtime)
					
					if not ok then
						return why
					end
				end
	
				return --> nothing, to end for loop
			end
		else
			return function ()
				local ok, why = self:loop()

				if not ok then
					return why
				end

				return --> nothing, to end for loop
			end
		end
	end) -- core:errors


	core.loader = loader

	return core
end -- loader

return loader(loader, ...)
