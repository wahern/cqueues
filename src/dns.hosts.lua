local loader = function(loader, ...)
	local hosts = require"_cqueues.dns.hosts"

	hosts.loadfile = function (file, syntax)
		local hosts = hosts.new()

		hosts:loadfile(file, syntax)

		return hosts
	end

	hosts.loadpath = function (path, syntax)
		local hosts = hosts.new()

		hosts:loadpath(path, syntax)

		return hosts
	end

	return hosts
end

return loader(loader, ...)
