local core = require("cqueues.core")

function core.poll(...)
	return coroutine.yield(...)
end -- core.poll

return core
