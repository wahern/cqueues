local loader = function(loader, ...)
	local core = require("_cqueues")
	local monotime = core.monotime

	function core.poll(...)
		return coroutine.yield(...)
	end -- core.poll

	function core.sleep(timeout)
		core.poll(timeout)
	end -- core.sleep

	local step = core.interpose("step", function (self, timeout)
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
