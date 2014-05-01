local loader = function(loader, ...)

local socket = require("_cqueues.socket")
local cqueues = require("cqueues")
local errno = require("cqueues.errno")

local poll = cqueues.poll
local monotime = cqueues.monotime
local running = cqueues.running

local SOCK_STREAM = socket.SOCK_STREAM
local SOCK_DGRAM = socket.SOCK_DGRAM

local EAGAIN = errno.EAGAIN
local EPIPE = errno.EPIPE
local ETIMEDOUT = errno.ETIMEDOUT
local ENOTCONN = errno.ENOTCONN
local ENOTSOCK = errno.ENOTSOCK
local strerror = errno.strerror


local function def_onerror(con, op, why, level)
	if why == EPIPE then
		return EPIPE
	elseif why == ETIMEDOUT then
		return ETIMEDOUT
	else
		local msg = string.format("socket.%s: %s", op, strerror(why))
		error(msg, (level or 2) + 1)
	end
end -- def_onerror

socket.onerror(def_onerror)

local function oops(con, op, why, level)
	local onerror = con:onerror() or def_onerror

	con:seterror(why)

	return onerror(con, op, why, (level or 2)) --> no incr on tail call
end -- oops


local function timed_poll(self, deadline)
	if deadline then
		local curtime = monotime()

		if deadline <= curtime then
			return false
		end

		poll(self, deadline - curtime)

		return true
	else
		poll(self)

		return true
	end
end -- timed_poll


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
-- Yielding socket:listen
--
local listen_nb; listen_nb = socket.interpose("listen", function(self, timeout)
	local timeout = timeout or self:timeout()
	local deadline = timeout and (monotime() + timeout)
	local ok, why = listen_nb(self)

	while not ok do
		if why == EAGAIN then
			if not timed_poll(self, deadline) then
				return false, oops(self, "listen", ETIMEDOUT)
			end
		else
			return false, oops(self, "listen", why)
		end

		ok, why = listen_nb(self)
	end

	return true
end)


--
-- Yielding socket:accept
--
local accept_nb; accept_nb = socket.interpose("accept", function(self, timeout)
	local timeout = timeout or self:timeout()
	local deadline = timeout and (monotime() + timeout)
	local con, why = accept_nb(self)

	while not con do
		if why == EAGAIN then
			if not timed_poll(self, deadline) then
				return nil, oops(self, "accept", ETIMEDOUT)
			end
		else
			return nil, oops(self, "accept", why)
		end

		con, why = accept_nb(self)
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
local connect_nb; connect_nb = socket.interpose("connect", function(self, timeout)
	local timeout = timeout or self:timeout()
	local deadline = timeout and (monotime() + timeout)
	local ok, why = connect_nb(self)

	while not ok do
		if why == EAGAIN then
			if not timed_poll(self, deadline) then
				return false, oops(self, "connect", ETIMEDOUT)
			end
		else
			return false, oops(self, "connect", why)
		end

		ok, why = connect_nb(self)
	end

	return true
end)


--
-- Yielding socket:starttls
--
local stls_nb; stls_nb = socket.interpose("starttls", function(self, arg1, arg2)
	local ctx, timeout

	if type(arg1) == "userdata" then
		ctx = arg1
	elseif type(arg2) == "userdata" then
		ctx = arg2
	end

	if type(arg1) == "number" then
		timeout = arg1
	elseif type(arg2) == "number" then
		timeout = arg2
	else
		-- NOTE: Backwards compatibility for old behavior, where an
		-- absent timeout simply returned immediately without
		-- polling.
		--
		-- Earlier code examples called :starttls outside of the
		-- event loop, and so we cannot yield in those cases without
		-- needlessly breaking such code.
		if running() then
			return stls_nb(self, ctx)
		end

		timeout = self:timeout()
	end

	local deadline = timeout and monotime() + timeout
	local ok, why = stls_nb(self, ctx)

	while not ok do
		if why == EAGAIN then
			if not timed_poll(self, deadline) then
				return false, oops(self, "starttls", ETIMEDOUT)
			end
		else
			return false, oops(self, "starttls", why)
		end

		ok, why = stls_nb(self, ctx)
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
local flush_nb;

local function flush_timed(self, mode, timeout, level)
	local ok, why = flush_nb(self, mode)

	if not ok then
		local deadline = timeout and (monotime() + timeout)

		repeat
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return false, oops(self, "flush", ETIMEDOUT, level + 1)
				end
			else
				return false, oops(self, "flush", why, level + 1)
			end

			ok, why = flush_nb(self, mode)
		until ok
	end

	return true
end -- flush_timed

flush_nb = socket.interpose("flush", function (self, arg1, arg2)
	local mode, timeout

	if type(arg1) == "string" then
		mode = arg1
	elseif type(arg2) == "string" then
		mode = arg2
	end

	if type(arg1) == "number" then
		timeout = arg1
	elseif type(arg2) == "number" then
		timeout = arg2
	else
		timeout = self:timeout()
	end

	return flush_timed(self, mode, timeout, 2)
end)


--
-- Yielding socket:read, built on non-blocking socket.recv
--
local function read(self, func, what, ...)
	if not what then
		return
	end

	local data, why = self:recv(what)

	if not data then
		local timeout = self:timeout()
		local deadline = timeout and (monotime() + timeout)

		repeat
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return nil, oops(self, func, ETIMEDOUT, 2)
				end
			elseif why then
				return nil, oops(self, func, why, 2)
			else -- EOF
				return
			end

			data, why = self:recv(what)
		until data
	end

	return data, read(self, func, ...)
end

socket.interpose("read", function(self, what, ...)
	if what then
		return read(self, "read", what, ...)
	else
		return read(self, "read", "*l")
	end
end)


--
-- Yielding socket:write
--
-- This is complicated by the fact that we want error messages to get the
-- correct stack trace, and also because on failure we want to return a list
-- of error values of indeterminate length.
--
local writeall; writeall = function(self, data, ...)
	if not data then
		return self
	end

	data = tostring(data)

	local i = 1

	while i <= #data do
		-- use only full buffering mode here to minimize socket I/O
		local n, why = self:send(data, i, #data, "f")

		i = i + n

		if i <= #data then
			if why == EAGAIN then
				local timeout = self:timeout()
				local deadline = timeout and (monotime() + timeout)

				if not timed_poll(self, deadline) then
					return nil, oops(self, "write", ETIMEDOUT, 3)
				end
			else
				return nil, oops(self, "write", why, 3)
			end
		end
	end

	return writeall(self, ...)
end

local function fileresult(self, ok, ...)
	if ok then
		return self
	else
		return nil, ...
	end
end -- fileresult

local function flushwrite(self, ok, ...)
	if not ok then
		return nil, ...
	end

	-- Flush the buffer here because we used full buffering mode in
	-- writeall. But pass empty mode so it uses the configured flushing
	-- mode instead of an implicit flush all.
	return fileresult(self, flush_timed(self, "", nil, 2))
end -- flushwrite

socket.interpose("write", function (self, ...)
	return flushwrite(self, writeall(self, ...))
end)


--
-- socket:lines
--
-- NOTE: optimize single-mode case so we're not unpacking tables all the
-- time.
--
local unpack = assert(table.unpack or unpack)

socket.interpose("lines", function (self, mode, ...)
	local args = select("#", ...) > 0 and { ... }

	if mode then
		if select("#", ...) > 0 then
			local args = { ... }

			return function ()
				return read(self, "lines", mode, unpack(args))
			end
		end
	else
		mode = "*l"
	end

	return function ()
		return read(self, "lines", mode)
	end
end)


--
-- socket:sendfd
--
local sendfd; sendfd = socket.interpose("sendfd", function (self, msg, fd)
	local timeout = self:timeout()
	local deadline = timeout and (monotime() + timeout)
	local ok, why

	repeat
		ok, why = sendfd(self, msg, fd)

		if not ok then
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return false, oops(self, "sendfd", ETIMEDOUT)
				end
			else
				return false, oops(self, "sendfd", why)
			end
		end
	until ok

	return ok
end)


--
-- socket:recvfd
--
local recvfd; recvfd = socket.interpose("recvfd", function (self, prepbufsiz)
	local timeout = self:timeout()
	local deadline = timeout and (monotime() + timeout)
	local msg, fd, why

	repeat
		msg, fd, why = recvfd(self, prepbufsiz)

		if not msg then
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return nil, nil, oops(self, "recvfd", ETIMEDOUT)
				end
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
	local ok, why = pack(self, num, nbits, mode)

	if not ok then
		local timeout = self:timeout()
		local deadline = timeout and (monotime() + timeout)

		repeat
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return false, oops(self, "pack", ETIMEDOUT)
				end
			else
				return false, oops(self, "pack", why)
			end

			ok, why = pack(self, num, nbits, mode)
		until ok
	end

	return ok
end)


--
-- socket:unpack
--
local unpack; unpack = socket.interpose("unpack", function (self, nbits)
	local num, why = unpack(self, nbits)

	if not num then
		local timeout = self:timeout()
		local deadline = timeout and (monotime() + timeout)

		repeat
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return nil, oops(self, "unpack", ETIMEDOUT)
				end
			else
				return nil, oops(self, "unpack", why)
			end

			num, why = unpack(self, nbits)
		until num
	end

	return num
end)


--
-- socket:fill
--
local fill; fill = socket.interpose("fill", function (self, size, timeout)
	local ok, why = fill(self, size)

	if not ok then
		local timeout = timeout or self:timeout()
		local deadline = timeout and (monotime() + timeout)

		repeat
			if why == EAGAIN then
				if not timed_poll(self, deadline) then
					return false, oops(self, "fill", ETIMEDOUT)
				end
			else
				return false, oops(self, "fill", why)
			end

			ok, why = fill(self, size)
		until ok
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
