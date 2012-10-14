local loader = function(loader, ...)
	local cqueues = require"cqueues"
	local config = require"_cqueues.dns.config"

	config.loadfile = function (file, syntax)
		local cfg = config.new()

		cfg:loadfile(file, syntax)

		return cfg
	end

	config.loadpath = function (path, syntax)
		local cfg = config.new()

		cfg:loadpath(path, syntax)

		return cfg
	end

	local build = config.new; config.new = function(init)
		local cfg = build()

		if init then
			if init.nameserver then
				cfg:setns(init.nameserver)
			end

			if init.search then
				cfg:setsearch(init.search)
			end

			if init.lookup then
				cfg:setlookup(init.lookup)
			end

			local opts = init.options or init.opts or { }
			local copy = {
				"edns0", "ndots", "timeout", "attempts",
				"rotate", "recurse", "smart", "tcp"
			}

			for i, k in ipairs(copy) do
				if opts[k] == nil and init[k] ~= nil then
					opts[k] = init[k];
				end
			end

			cfg:setopts(opts)

			if init.interface then
				cfg:setiface(init.interface)
			end
		end

		return cfg
	end

	config.interpose("totable", function (self)
		return {
			nameserver = self:getns(),
			search = self:getsearch(),
			lookup = self:getlookup(),
			options = self:getopts(),
			interface = self:getiface(),
		}
	end)

	return config
end

return loader(loader, ...)
