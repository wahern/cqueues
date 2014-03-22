local loader = function(loader, ...)

local socket = require("_cqueues.socket")
local cqueues = require("cqueues")
local errno = require("cqueues.errno")

local poll = cqueues.poll
local monotime = cqueues.monotime

local SOCK_STREAM = socket.SOCK_STREAM
local SOCK_DGRAM = socket.SOCK_DGRAM

local EAGAIN = errno.EAGAIN
local EPIPE = errno.EPIPE
local ETIMEDOUT = errno.ETIMEDOUT
local ENOTCONN = errno.ENOTCONN
local ENOTSOCK = errno.ENOTSOCK
local strerror = errno.strerror


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
-- Yielding socket.pair
--
local pair = socket.pair; socket.pair = function(type)
	if type == "stream" then
		type = SOCK_STREAM
	elseif type == "dgram" then
		type = SOCK_DGRAM
	end

	return pair(type)
end


--
-- Throwable socket:setbufsiz
--
local setbufsiz; setbufsiz = socket.interpose("setbufsiz", function(self, input, output)
	local input, output, why = setbufsiz(self, input, output)

	if not input then
		return nil, nil, oops(self, "setbufsiz", why)
	end

	return input, output
end)


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

				poll(self, deadline - curtime)
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
-- Yielding socket:connect
--
local oconnect; oconnect = socket.interpose("connect", function(self, timeout)
	local deadline = (timeout and (monotime() + timeout)) or nil
	local ok, why = oconnect(self)

	while not ok do
		if why == EAGAIN then
			local curtime = monotime()

			if deadline then
				if deadline <= curtime then
					return false, oops(self, "connect", ETIMEDOUT)
				end

				poll(self, deadline - curtime)
			else
				poll(self)
			end
		else
			return false, oops(self, "connect", why)
		end

		ok, why = oconnect(self, mode)
	end

	return true
end)


--
-- socket:starttls
--
local starttls; starttls = socket.interpose("starttls", function(self, ...)
	local nargs = select("#", ...)
	local arg1, arg2 = ...
	local ctx, timeout

	if nargs == 0 then
		return starttls(self)
	elseif nargs == 1 then
		if type(arg1) == "userdata" then
			return starttls(self, arg1)
		end

		timeout = arg1
	else
		ctx = arg1
		timeout = arg2
	end

	local deadline = timeout and monotime() + timeout
	local ok, why = starttls(self, ctx)

	while not ok do
		if why == EAGAIN then
			if deadline then
				local curtime = monotime()

				if curtime >= deadline then
					return false, oops(self, "starttls", ETIMEDOUT)
				end

				poll(self, deadline - curtime)
			else
				poll(self)
			end
		else
			return false, oops(self, "starttls", why)
		end

		ok, why = starttls(self, ctx)
	end

	return true
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

	while not data and why do
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


--
-- socket:fill
--
local fill; fill = socket.interpose("fill", function (self, size, timeout)
	local ok, why = fill(self, size)
	local deadline = timeout and monotime() + timeout

	while not ok do
		if why == EAGAIN then
			if deadline then
				local curtime = monotime()

				if deadline <= curtime then
					return false, oops(self, "fill", why)
				end

				poll(self, deadline - curtime)
			else
				poll(self)
			end
		else
			return false, oops(self, "fill", why)
		end

		ok, why = fill(self, size)
	end

	return true
end)


--
-- socket:peername
--
local function getname(get, self)
	local af, r1, r2 = get(self)

	if af then
		return af, r1, r2
	elseif r1 == ENOTCONN or r1 == ENOTSOCK or r1 == EAGAIN then
		return 0
	else
		return nil, r1
	end
end

local peername; peername = socket.interpose("peername", function (self)
	return getname(peername, self)
end)


--
-- socket:localname
--
local localname; localname = socket.interpose("localname", function (self)
	return getname(localname, self)
end)


socket.loader = loader

return socket

end -- loader

return loader(loader, ...)
