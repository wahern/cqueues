local loader = function(loader, ...)
	local packet = require"_cqueues.dns.packet"

	return packet
end

return loader(loader, ...)
