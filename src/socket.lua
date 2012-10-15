local loader = function(loader, ...)

local socket = require("_cqueues.socket")
local cqueues = require("cqueues")
local errno = require("cqueues.errno")

local poll = cqueues.poll
local monotime = cqueues.monotime

local EAGAIN = errno.EAGAIN;
local EPIPE = errno.EPIPE;
local ETIMEDOUT = errno.ETIMEDOUT;
local strerror = errno.strerror;


local function oops(con, op, why)
	local onerror = con:onerror()

	if onerror then
		return onerror(con, op, why)
	elseif why == EPIPE then
		return EPIPE
	elseif why == ETIMEDOUT then
		return ETIMEDOUT
	else
		local msg = string.format("socket.%s: %s", op, strerror(why))
		error(msg)
	end
end -- oops


--
-- Yielding socket:accept
--
local oaccept; oaccept = socket.interpose("accept", function(self, timeout)
	local deadline = (timeout and (monotime() + timeout)) or nil
	local con, why = oaccept(self)

	while not con do
		if why == EAGAIN then
			local curtime = monotime()

			if deadline then
				if deadline <= curtime then
					return nil, oops(self, "accept", ETIMEDOUT)
				end

				poll(self, { timeout = function() return curtime - deadline end })
			else
				poll(self)
			end
		else
			return nil, oops(self, "accept", why)
		end

		con, why = oaccept(self)
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
-- socket:checktls
--
local havessl, whynossl

local checktls; checktls = socket.interpose("checktls", function(self)
	if not havessl then
		if havessl == false then
			return nil, whynossl
		end

		local havessl, whynossl = pcall(require, "openssl.ssl")

		if not havessl then
			return nil, whynossl
		end
	end

	return checktls(self)
end)


--
-- Yielding socket:flush
--
local oflush; oflush = socket.interpose("flush", function(self, mode)
	local ok, why = oflush(self, mode)

	while not ok do
		if why == EAGAIN then
			poll(self)
		else
			return false, oops(self, "flush", why)
		end

		ok, why = oflush(self, mode)
	end

	return true
end)


--
-- Yielding socket:read, built on non-blocking socket.recv
--
local function read(self, what, ...)
	if not what then
		return
	end

	local data, why = self:recv(what)

	while not data do
		if why == EAGAIN then
			poll(self)
		else
			return nil, oops(self, "read", why)
		end

		data, why = self:recv(what)
	end

	return data, read(self, ...)
end

socket.interpose("read", function(self, ...)
	return read(self, ... or "*l")
end)


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
		local n, why = self:send(data, i, #data, "f")

		i = i + n

		if i <= #data then
			if why == EAGAIN then
				poll(self)
			else
				return nil, oops(self, "write", why)
			end
		end
	end

	return writeall(self, ...)
end

socket.interpose("write", function (self, ...)
	local ok, why = writeall(self, ...)

	if not ok then
		return nil, why
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
	local ok, why

	repeat
		ok, why = sendfd(self, msg, fd)

		if not ok then
			if why == EAGAIN then
				poll(self)
			else
				return nil, oops(self, "sendfd", why)
			end
		end
	until ok

	return ok
end)


--
-- socket:recvfd
--
local recvfd; recvfd = socket.interpose("recvfd", function (self, prepbufsiz)
	local msg, fd, why

	repeat
		msg, fd, why = recvfd(self, prepbufsiz)

		if not msg then
			if why == EAGAIN then
				poll(self)
			else
				return nil, nil, oops(self, "recvfd", why)
			end
		end
	until msg

	return msg, fd
end)


--
-- socket:pack
--
local pack; pack = socket.interpose("pack", function (self, num, nbits, mode)
	local ok, why

	repeat
		ok, why = pack(self, num, nbits, mode)

		if not ok then
			if why == EAGAIN then
				poll(self)
			else
				return false, oops(self, "pack", why)
			end
		end
	until ok

	return ok
end)


--
-- socket:unpack
--
local unpack; unpack = socket.interpose("unpack", function (self, nbits)
	local num, why

	repeat
		num, why = unpack(self, nbits)

		if not num then
			if why == EAGAIN then
				poll(self)
			else
				return nil, oops(self, "unpack", why)
			end
		end
	until num

	return num
end)

socket.loader = loader

return socket

end -- loader

return loader(loader, ...)
