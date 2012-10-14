local loader = function(loader, ...)
	local cqueues = require"cqueues"
	local resolver = require"_cqueues.dns.resolver"
	local errno = require"cqueues.errno"
	local EAGAIN = errno.EAGAIN
	local ETIMEDOUT = errno.ETIMEDOUT
	local monotime = cqueues.monotime

	resolver.interpose("query", function (self, name, type, class, timeout)
		local deadline = timeout and (monotime() + timeout)
		local ok, why, answer

		ok, why = self:submit(name, type, class)

		if not ok then
			return nil, why
		end

		repeat
			answer, why = self:fetch()

			if not answer then
				if why == EAGAIN then
					if deadline then
						local curtime = monotime()

						if deadline < curtime then
							return nil, ETIMEDOUT
						else
							cqueues.poll(self, math.min(deadline - curtime, 1))
						end
					else
						cqueues.poll(self, 1)
					end
				else
					return nil, why
				end
			end
		until answer

		return answer
	end)

	return resolver
end

return loader(loader, ...)
