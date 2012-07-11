local core = require("_cqueues")

function core.poll(...)
	return coroutine.yield(...)
end -- core.poll

return core
