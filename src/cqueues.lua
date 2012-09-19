local loader = function(loader, ...)
	local core = require("_cqueues")

	function core.poll(...)
		return coroutine.yield(...)
	end -- core.poll

	function core.sleep(timeout)
		core.poll(timeout)
	end -- core.sleep

	core.loader = loader

	return core
end -- loader

return loader(loader, ...)
