local loader = function(loader, ...)
	local cqueues = require"cqueues"
	local hints = require"_cqueues.dns.hints"

	return hints
end

return loader(loader, ...)
