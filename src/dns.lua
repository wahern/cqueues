local loader = function(loader, ...)
	local dns = require"_cqueues.dns"

	dns.loader = loader

	return dns
end

return loader(loader, ...)
