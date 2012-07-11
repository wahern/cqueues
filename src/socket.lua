local socket = require("cqueues.socket.core")
local cqueues = require("cqueues")
local errno = require("cqueues.errno")

--
-- Yielding socket:flush
--
local oflush; oflush = socket.interpose("flush", function(self, mode)
	local ok, syserr = oflush(self, mode)

	while not ok do
		if syserr == errno.EAGAIN then
			cqueues.poll(self)
		elseif syserr == errno.EPIPE then
			return false, errno.strerror(syserr)
		else
			error("socket.flush: " .. errno.strerror(syserr))
		end

		ok, syserr = oflush(self, mode)
	end

	return true
end)


--
-- Yielding socket:read, built on non-blocking socket.recv
--
local nread;

nread = function(self, what, ...)
	if not what then
		return
	end

	local data, syerr = self:recv(what)

	while not data do
		if syerr == errno.EAGAIN then
			cqueues.poll(self)
		elseif syerr == errno.EPIPE then
			return nil
		else
			error("socket.recv: " .. errno.strerror(syerr))
		end

		data, syerr = self:recv(what)
	end

	return data, nread(self, ...)
end

socket.interpose("read", nread)


--
-- Yielding socket:write, built on non-blocking socket.send
--
local writeall; writeall = function(self, data, ...)
	if not data then
		return self
	end

	data = tostring(data)

	local i = 1

	while i <= #data do
		-- use only full buffering mode here
		local n, syerr = self:send(data, i, #data, "f")

		i = i + n

		if i <= #data then
			if syerr == errno.EAGAIN then
				cqueues.poll(self)
			elseif syerr == errno.EPIPE then
				return nil, errno.strerror(syerr)
			else
				return nil, errno.strerror(syerr)
			end
		end
	end

	return writeall(self, ...)
end

socket.interpose("write", function (self, ...)
	local ok, err = writeall(self, ...)

	if not ok then
		return nil, err
	end

	-- writeall returns once all data is written, even if just to the
	-- buffer. Flush the buffer here, but pass empty mode so it uses the
	-- configured flushing mode instead of an implicit flush all.
	return self:flush("")
end)


--
-- socket:lines
--
socket.interpose("lines", function (self, mode)
	return function()
		return self:read(mode or "*l")
	end
end)


return socket
