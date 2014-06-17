local loader = function(loader, ...)
	local resolver = require"cqueues.dns.resolver"
	local config = require"cqueues.dns.config"
	local condition = require"cqueues.condition"
	local monotime = require"cqueues".monotime
	local random = require"cqueues.dns".random
	local errno = require"cqueues.errno"
	local ETIMEDOUT = errno.ETIMEDOUT


	local function todeadline(timeout)
		return (timeout and (monotime() + timeout)) or nil
	end -- todeadline

	local function totimeout(deadline)
		return (deadline and math.max(0, deadline - monotime())) or nil
	end -- totimeout


	--
	-- NOTE: Keep track of an unordered collection of objects, and in
	-- particular a count of objects in the collection. If an object is
	-- garbage collected automatically decrement the count and signal
	-- the condition variable.
	--
	local alive = {}

	function alive.new(condvar)
		local self = setmetatable({}, { __index = alive })

		self.n = 0
		self.table = setmetatable({}, { __mode = "k" })
		self.condvar = condvar
		self.hooks = {}
		self.hookmt = { __gc = function (hook)
			self.n = self.n - 1
			self.condvar:signal()

			if hook.debug ~= false then
				io.stderr:write("reclaiming resolver\n")
			end
		end }

		return self
	end -- alive.new


	function alive:add(x, debug)
		if not self.table[x] then
			local hook = self.hooks[#self.hooks]

			if hook then
				self.hooks[#self.hooks] = nil
			else
				hook = setmetatable({}, self.hookmt)
			end

			hook.debug = debug
			self.table[x] = hook
			self.n = self.n + 1
		end
	end -- alive:add


	function alive:delete(x)
		if self.table[x] then
			self.table[x].debug = false
			self.hooks[#self.hooks + 1] = self.table[x]
			self.table[x] = nil
			self.n = self.n - 1
			self.condvar:signal()
		end
	end -- alive:delete


	function alive:check()
		local n = 0

		for _ in pairs(self.table) do
			n = n + 1
		end

		return assert(n == self.n, "resolver registry corrupt")
	end -- alive:check


	local pool = {}

	local function tryget(self)
		local res, why

		if #self.cache > 1 then
			res = self.cache[#self.cache]
			self.cache[#self.cache] = nil
		elseif self.alive.n < self.hiwat then
			res, why = resolver.new(self.resconf, self.hosts, self.hints)

			if not res then
				return nil, why
			end
		end

		if res then
			self.alive:add(res, self.debug)
		end

		return res
	end -- tryget

	local function getby(self, deadline)
		local res, why = tryget(self)

		while not res and not why do
			if deadline and deadline <= monotime() then
				return nil, ETIMEDOUT
			else
				self.condvar:wait(totimeout(deadline))
				res, why = tryget(self)
			end
		end

		return res, why
	end -- getby


	function pool:get(timeout)
		return getby(self, todeadline(timeout))
	end -- pool:get


	function pool:put(res)
		self.alive:delete(res)

		if #self.cache < self.lowat and res:stat().queries < self.querymax then
			self.cache[#self.cache + 1] = res

			if not self.lifo and #self.cache > 1 then
				local i = random(#self.cache) + 1

				self.cache[#self.cache] = self.cache[i]
				self.cache[i] = res
			end
		else
			res:close()
		end
	end -- pool:put


	function pool:signal()
		self.condvar:signal()
	end -- pool:signal


	function pool:query(name, type, class, timeout) 
		local deadline = todeadline(timeout or self.timeout)
		local res, why = getby(self, deadline)

		if not res then
			return nil, why
		end

		local pkt, why = res:query(name, type, class, totimeout(deadline))

		if not self.debug then
			self:put(res)
		end

		return pkt, why
	end -- pool:query


	local resolvers = {}

	resolvers.lowat = 1
	resolvers.hiwat = 32
	resolvers.querymax = 2048
	resolvers.debug = nil
	resolvers.lifo = false

	function resolvers.new(resconf, hosts, hints)
		local self = {}

		self.resconf = (type(resconf) == "table" and config.new(resconf)) or resconf
		self.hosts = hosts
		self.hints = hints
		self.condvar = condition.new()
		self.lowat = resolvers.lowat
		self.hiwat = resolvers.hiwat
		self.timeout = resolvers.timeout
		self.querymax = resolvers.querymax
		self.debug = resolvers.debug
		self.lifo = resolvers.lifo
		self.cache = {}
		self.alive = alive.new(self.condvar)

		return setmetatable(self, { __index = pool })
	end -- resolvers.new


	function resolvers.stub(cfg)
		return resolvers.new(config.stub(cfg))
	end -- resolvers.stub


	function resolvers.root(cfg)
		return resolvers.new(config.root(cfg))
	end -- resolvers.root


	function resolvers.type(o)
		local mt = getmetatable(o)

		if mt and mt.__index == pool then
			return "dns resolver pool"
		end
	end -- resolvers.type


	resolvers.loader = loader

	return resolvers
end

return loader(loader, ...)
