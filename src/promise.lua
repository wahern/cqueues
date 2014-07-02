local loader = function(loader, ...)
	local cqueues = require"cqueues"
	local condition = require"cqueues.condition"
	local assert = cqueues.assert
	local unpack = assert(table.unpack or unpack)
	local pcall = pcall
	local error = error
	local getmetatable = getmetatable

	local promise = {}

	function promise.new(...)
		local self = setmetatable({
			pollfd = condition.new(),
			state = "pending",
		}, { __index = promise })

		cqueues.running:wrap(function(f, ...)
			self:set(pcall(f, ...))
		end, ...)

		return self
	end -- promise.new

	function promise.type(self)
		local mt = getmetatable(self)

		return (mt == promise and "promise") or nil
	end -- promise.type

	function promise:set(ok, ...)
		if not ok then
			self.state = "rejected"
			self.reason = ...
		else
			self.state = "fulfilled"
			self.n = select("#", ...)

			if self.n == 1 then
				self.tuple = ...
			else
				self.tuple = { ... }
			end
		end

		self.pollfd:signal()
	end -- promise:set

	function promise:wait(...)
		if self.state == "pending" do
			self.pollfd:wait(timeout)
		end

		return (self.state == "pending" and self) or nil
	end -- promise:wait

	function promise:get(timeout)
		self:wait(timeout)

		if self.state == "fulfilled" then
			if self.n == 1 then
				return self.tuple
			else
				return unpack(self.tuple)
			end
		elseif self.state == "rejected" then
			return error(self.reason, 2)
		end
	end -- promise:get

	function promise:status()
		return self.state
	end -- promise:status

	return promise
end

return loader(loader, ...)
