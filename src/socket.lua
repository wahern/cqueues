local socket = require("_cqueues.socket")
local cqueues = require("cqueues")
local errno = require("cqueues.errno")

local poll = cqueues.poll
local monotime = cqueues.monotime

local EAGAIN = errno.EAGAIN;
local EPIPE = errno.EPIPE;


--
-- Yielding socket:accept
--
local oaccept; oaccept = socket.interpose("accept", function(self, timeout)
	local deadline = (timeout and (monotime() + timeout)) or nil
	local con, syerr = oaccept(self)

	while not con do
		if syerr == EAGAIN then
			local curtime = monotime()

			if deadline then
				if deadline <= curtime then
					return nil
				end

				poll(self, { timeout = function() return curtime - deadline end })
			else
				poll(self)
			end
		else
			error("socket.flush: " .. errno.strerror(syerr))
		end

		con, syerr = oaccept(self)
	end

	return con
end)


--
-- socket:clients
--
socket.interpose("clients", function(self, timeout)
	return function() return self:accept(timeout) end
end)


--
-- Yielding socket:flush
--
local oflush; oflush = socket.interpose("flush", function(self, mode)
	local ok, syserr = oflush(self, mode)

	while not ok do
		if syserr == EAGAIN then
			poll(self)
		elseif syserr == EPIPE then
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
local nread; nread = function(self, what, ...)
	if not what then
		return
	end

	local data, syerr = self:recv(what)

	while not data do
		if syerr == EAGAIN then
			poll(self)
		elseif syerr == EPIPE then
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
			if syerr == EAGAIN then
				poll(self)
			elseif syerr == EPIPE then
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


--
-- socket:sendfd
--
local sendfd; sendfd = socket.interpose("sendfd", function (self, msg, fd)
	local ok, err

	repeat
		ok, err = sendfd(self, msg, fd)

		if not ok and err == EAGAIN then
			poll(self)
		end
	until ok or err ~= EAGAIN

	return ok, err and errno.strerror(err) or nil
end)


--
-- socket:recvfd
--
local recvfd; recvfd = socket.interpose("recvfd", function (self, prepbufsiz)
	local msg, fd, err

	repeat
		msg, fd, err = recvfd(self, prepbufsiz)

		if not msg and err == EAGAIN then
			poll(self)
		end
	until msg or err ~= EAGAIN

	return msg, fd, err and errno.strerror(err) or nil
end)


--
-- socket:pack
--
local pack; pack = socket.interpose("pack", function (self, num, nbits, mode)
	local ok, why

	repeat
		ok, why = pack(self, num, nbits, mode)

		if not ok and why == EAGAIN then
			poll(self)
		end
	until ok or why ~= EAGAIN

	return ok, why
end)


--
-- socket:unpack
--
local unpack; unpack = socket.interpose("unpack", function (self, nbits)
	local num, why

	repeat
		num, why = unpack(self, nbits)

		if not num and why == EAGAIN then
			poll(self)
		end
	until num or why ~= EAGAIN

	return num, why
end)


return socket
