local loader = function(loader, ...)
	local cqueues = require"cqueues"
	local resolver = require"_cqueues.dns.resolver"
	local EAGAIN = require"cqueues.errno".EAGAIN


	resolver.interpose("query", function(self, name, type, class)
		local ok, why, pkt

		ok, why = self:submit(name, type, class)

		if not ok then
			return nil, why
		end

		repeat
			pkt, why = self:fetch()

			if not pkt then
				if why == EAGAIN then
					cqueues.poll(self)
				else
					return nil, why
				end
			end
		until pkt

		return pkt
	end)

	return resolver
end

return loader(loader, ...)
