local loader = function(loader, ...)
	local core = require"_cqueues"
	local errno = require"_cqueues.errno"
	local monotime = core.monotime
	local running = core.running
	local strerror = errno.strerror

	-- lazily load auxlib to prevent circular or unused dependencies
	local auxlib = setmetatable({}, { __index = function (t, k)
		local v = require"cqueues.auxlib"[k]
		rawset(t, k, v)
		return v
	end })

	-- load deprecated APIs into shadow table to keep hidden unless used
	local notsupp = {}
	setmetatable(core, { __index = notsupp })

	--
	-- core.poll
	--
	-- Wrap the cqueues yield protocol to support polling across
	-- multilevel resume/yield. Requires explicit or implicit use
	-- (through monkey patching of coroutine.resume and coroutine.wrap)
	-- of auxlib.resume or auxlib.wrap.
	--
	-- Also supports polling from outside of a running event loop using
	-- a cheap hack. NOT RECOMMENDED.
	--
	local _POLL = core._POLL
	local yield = coroutine.yield
	local poller

	function core.poll(...)
		local yes, main = running()

		if yes then
			if main then
				return yield(...)
			else
				return yield(_POLL, ...)
			end
		else
			local tuple

			poller = poller or auxlib.assert3(core.new())

			poller:wrap(function (...)
				tuple = { core.poll(...) }
			end, ...)

			auxlib.assert3(poller:step())

			if tuple then
				return table.unpack(tuple)
			end
		end
	end -- core.poll

	--
	-- core.sleep
	--
	-- Sleep primitive. 
	--
	function core.sleep(timeout)
		core.poll(timeout)
	end -- core.sleep

	--
	-- core:step
	--
	-- Wrap the low-level :step interface to make managing event loops
	-- slightly easier.
	--
	local step; step = core.interpose("step", function (self, timeout)
		if core.running() then
			core.poll(self, timeout)

			return step(self, 0.0)
		else
			return step(self, timeout)
		end
	end) -- core:step

	--
	-- core:loop
	--
	-- Step until an error is encountered.
	--
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

	--
	-- core:errors
	--
	-- Return iterator over core:loop.
	--
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

	--
	-- core.assert
	--
	-- DEPRECATED. See auxlib.assert.
	--
	function notsupp.assert(...)
		return auxlib.assert(...)
	end -- notsupp.assert

	--
	-- core.resume
	--
	-- DEPRECATED. See auxlib.resume.
	--
	function notsupp.resume(...)
		return auxlib.resume(...)
	end -- notsupp.resume

	--
	-- core.wrap
	--
	-- DEPRECATED. See auxlib.wrap.
	--
	function notsupp.wrap(...)
		return auxlib.wrap(...)
	end -- notsupp.wrap

	core.loader = loader

	return core
end -- loader

return loader(loader, ...)
