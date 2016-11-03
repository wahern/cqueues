local debug = require"_cqueues.socket.debug"


--
-- toviz - binary to visible ASCII string
--
local _viz = {
	["\a"] = "\\a", ["\b"] = "\\b", ["\f"] = "\\f", ["\n"] = "\\n",
	["\r"] = "\\r", ["\t"] = "\\t", ["\v"] = "\\v", ["\\"] = "\\\\",
	['"'] = '\\"', ["'"] = "\\'"
}

for i = 0,255 do
	local c = string.char(i)
	_viz[c] = _viz[c] or (i > 31 and i < 127 and c) or string.format("\\%.3d", i)
end

local function toviz(txt)
	return (string.gsub(tostring(txt), ".", _viz))
end -- toviz


--
-- huh - print arguments to stderr before returning to caller
--
local function huh(...)
	local function _huh(...)
		if select("#", ...) > 0 then
			local x = ...

			if type(x) == "string" or type(x) == "table" or type(x) == "userdata" then
				x = string.format('"%s"', toviz(x))
			end

			io.stderr:write(tostring(x), " ")

			return (...), _huh(select(2, ...))
		end
	end

	io.stderr:write"[ "
	_huh(...)
	io.stderr:write("] (line ", _G.debug.getinfo(2, "l").currentline , ")\n")

	return ...
end -- huh


--
-- Simple semaphore
--
local semaphore = {}

function semaphore.new()
	return setmetatable({
		counter = 0,
		condvar = assert(require"cqueues.condition".new()),
	}, { __index = semaphore })
end -- semaphore.new

function semaphore:post()
	self.counter = self.counter + 1
	self.condvar:signal()
end -- semaphore:post

function semaphore:wait()
	while self.counter == 0 do
		self.condvar:wait()
	end

	self.counter = self.counter - 1
end -- semaphore:wait


--
-- iobox - provide environment for running cqueues code
--
local function iobox(f)
	return function()
		local cqueues = require"cqueues"
		local loop = cqueues.running()

		if loop then
			f(loop)
		else
			local loop = cqueues.new()
			assert(loop:wrap(function() f(loop) end):loop())
		end
	end
end -- iobox


--
-- debug.units - table of unit tests
--
debug.units = setmetatable({ }, { __index = {
	new = function(name, f)
		debug.units[name] = f
		debug.units[#debug.units + 1] = { name = name, f = f }
	end,

	run = function(patt)
		patt = patt or "."

		for _, unit in ipairs(debug.units) do
			if string.match(unit.name, patt) then
				unit.f()
			end
		end
	end
} })


--
-- iov_eoh consumes a multi-line MIME header at the beginning of the source
-- text. Returns the prefix length of the header. A return value greater
-- than #text means more text is necessary.
--
-- On error returns nil, error string, and error number.
--
debug.units.new("iov_eoh", function()
	local iov_eoh = debug.iov_eoh -- (text, eof)

	local txt = "Foo: bar\n"
	local n = assert(iov_eoh(txt, false))
	assert(n > #txt)

	--
	-- 2014-05-26: Only headers with a valid termination condition will
	-- parse. A header which is followed by EOF, even with a trailing
	-- newline, is not considered a valid header. Likewise for headers
	-- which reach the maximum line length.
	--
	local txt = "Foo: bar\n \n\tbaz\n\n"
	local n = assert(iov_eoh(txt, true))
	assert(n == #txt - 1)

	local txt = "Foo: bar\n\n"
	local n = assert(iov_eoh(txt, false))
	assert(n == #txt - 1)

	-- skips over spaces before colon
	local txt = "Foo : bar\n\n"
	local n = assert(iov_eoh(txt, false))
	print(n)
	assert(n == #txt - 1)

	-- make sure we handle end-of-headers linebreak
	local txt = "\n"
	local n = assert(iov_eoh(txt, false))
	assert(n == 0)

	-- make sure we stop at first non-header
	local txt = "foo\n"
	local n = assert(iov_eoh(txt, false))
	assert(n == 0)
end)


--
-- iov_eob consumes data up and including the specified MIME boundary
-- marker. Returns the prefix length of the chunk. A return value greater
-- than #text means more text is necessary. 0 means the boundary was
-- not found.
--
debug.units.new("iov_eob", function()
	local iov_eob = debug.iov_eob -- (text, boundary)

	local txt = "123--AAAA"
	local n = assert(iov_eob(txt, "--AAAA"))
	assert(n == #txt)

	local txt = "123--AAAA\n"
	local n = assert(iov_eob(txt, "--AAAA"))
	assert(n == #txt - 1)

	local txt = "123--AAAA"
	local n = assert(iov_eob(txt, "--AAAAA"))
	assert(n == 0)

	local txt = "--AAAA"
	local n = assert(iov_eob(txt, "--AAA"))
	assert(n == #txt - 1)
end)


--
-- iov_eot attempts to fit \r\n:\n translated text into the specified lower
-- and upper output string length bounds, without leaving any trailing \r,
-- unless EOF is true. Returns the prefix length of the input text necessary
-- to meet the minimum bound. A return value greater than #text means more
-- text is necessary. Specifically, the return value represents the minimum
-- string length needded to fit the lower bound. It could be more if the new
-- text has more \r\n-pairs.
--
-- On error returns nil, error string, and error number.
--
debug.units.new("iov_eot", function()
	local iov_eot = debug.iov_eot -- (text, minbuf, maxbuf, eof)

	local txt = "12345678\r"
	local n = assert(iov_eot(txt, #txt, #txt, false))
	assert(n > #txt)

	local txt = "\r12345678"
	local n = assert(iov_eot(txt, #txt, #txt, false))
	assert(n == #txt)

	local txt = "12345678\r"
	local n = assert(iov_eot(txt, #txt - 1, #txt, false))
	assert(n == #txt - 1)

	local txt = "\r\n"
	local n = assert(iov_eot(txt, #txt + 1, #txt + 1, false))
	assert(n == #txt + 2)

	local txt = "\r\n"
	local n = assert(iov_eot(txt, #txt + 1, #txt + 1, true))
	assert(n == #txt)

	local txt = string.rep("\r\n", 8192)
	local _, overflow = iov_eot(txt, -4096, -4096, false)
	assert(overflow)
end)


--
-- iov_trimcr removes \r from \r\n pairs. If chomp is true, then only removes
-- \r from ending \r\n pair. Returns translated string.
--
debug.units.new("iov_trimcr", function()
	local iov_trimcr = debug.iov_trimcr -- (text, chomp)

	for _, txt in pairs{ "1\r\n2\r\n3\r\n", "\r\n\r" } do
		local gs = string.gsub(txt, "\r\n", "\n")
		assert(gs == iov_trimcr(txt, false), string.format("%s != %s", toviz(gs), toviz(txt)))
	end
end)


--
-- iov_trimcrlf removes \r from \r\n pairs. If chomp is true, then only
-- removes \r\n from end of string. Returns translated string.
--
debug.units.new("iov_trimcrlf", function()
	local iov_trimcrlf = debug.iov_trimcrlf -- (text, chomp)

	for _, txt in pairs{ "\r\n.\r\r\r\n", "\r\n\r\r\r", "\r\r.\n\n" } do
		local gs = string.gsub(txt, "\r?\n", "")
		assert(gs == iov_trimcrlf(txt, false), string.format("%s != %s", toviz(gs), toviz(txt)))
	end

	for _, txt in pairs{ "\r\n.\r\n", "\n", "\n\r\n\n" } do
		local gs = string.gsub(txt, "\r?\n$", "")
		assert(gs == iov_trimcrlf(txt, true), string.format("%s != %s", toviz(gs), toviz(txt)))
	end
end)


--
-- io.boundary - test various aspects of buffered MIME reader
--
debug.units.new("io.boundary.text", iobox(function(loop)
	local cqueues = require"cqueues"
	local socket = require"cqueues.socket"

	local snd, rcv = assert(socket.pair())
	local boundary = "--AAAA"
	local message = string.rep(".\r\n.\r", 123456)

	snd:setmode(nil, "bf")
	snd:setbufsiz(nil, 1024)
	rcv:setmode("tf")
	rcv:setbufsiz(256)

	cqueues.running():wrap(function ()
		local sent = 1

		while sent <= #message do
			local n = math.random(math.min(1024, #message - sent))
			local buf = string.sub(message, sent, sent + n)

			snd:write(buf)
			sent = sent + #buf
		end

		snd:write(boundary)
		snd:flush()
		snd:shutdown()
	end)

	local buff = {}

	for b in rcv:lines(boundary) do
		if #buff > 0 then
			-- in text mode the implementation tries to break
			-- chunks along line boundaries, as long as they
			-- fall within MAX(maxline, bufsiz).
			assert(buff[#buff]:sub(-1) == "\n")
		end

		buff[#buff + 1] = b
	end

	assert(table.concat(buff) == string.gsub(message, "\r\n", "\n"))
	assert(rcv:read() == boundary)
end))


--
-- io.block - test various aspects of buffered block reader
--
debug.units.new("io.block.text", iobox(function(loop)
	local cqueues = require"cqueues"
	local socket = require"cqueues.socket"

	local snd, rcv = assert(socket.pair())
	local message = string.rep(".\r\n.\r", 123456) .. "@"
	snd:setmode(nil, "bf")
	snd:setbufsiz(nil, math.random(7, 1024))
	rcv:setmode("tf")
	rcv:setbufsiz(256)

	cqueues.running():wrap(function ()
		local sent = 0

		while sent < #message do
			local n = math.random(math.min(1024, #message - sent))
			local buf = string.sub(message, sent + 1, sent + n)

			snd:write(buf)
			sent = sent + #buf
		end

		snd:flush()
		snd:shutdown"w"
	end)

	local buff = {}

	for b in rcv:lines(127) do
		buff[#buff + 1] = b
	end

	assert(table.concat(buff) == string.gsub(message, "\r\n", "\n"))
end))


--
-- sys.reuseport - test SO_REUSEPORT
--
debug.units.new("sys.reuseport", iobox(function(loop)
	local socket = require"cqueues.socket"
	local A = assert(assert(socket.listen{ host = "127.0.0.1", port = 0, sin_reuseport = true }):listen())
	local _, _, port = assert(A:localname())
	local B = assert(assert(socket.listen{ host = "127.0.0.1", port = port, sin_reuseport = true }):listen())
	local sem = semaphore.new()
	local behavior = nil

	loop:wrap(function()
		sem:wait()
		assert(socket.connect("127.0.0.1", port)):connect(1)
		sem:wait()
		assert(socket.connect("127.0.0.1", port)):connect(1)
	end)

	loop:wrap(function()
		sem:post()
		if B:accept(1) then
			behavior = "bsd"
		end

		sem:post()
		if A:accept(1) then
			behavior = "linux"
		end

		io.stderr:write(string.format("sys.reuseport: %s\n", assert(behavior)))

		A:close()
		B:close()
	end)
end))


--
-- opts.cloexec -- test that socket.connect obeys .cloexec
--
debug.units.new("opts.cloexec", iobox(function (loop)
	local ok, unix = pcall(require, "unix")

	if not ok or not unix then
		return
	end

	local assert = require"cqueues.auxlib".assert
	local socket = require"cqueues.socket"
	local A = assert(assert(socket.listen{ host = "127.0.0.1", port = 0, sin_reuseport = true }):listen())
	local _, _, port = assert(A:localname())

	loop:wrap(function ()
		for _, cloexec in ipairs{ true, false } do
			local B = assert(assert(socket.connect{ host = "127.0.0.1", port = port, cloexec = cloexec }):connect())
			local flags = assert(unix.fcntl(B:pollfd(), unix.F_GETFD))

			--io.stderr:write(string.format("opts.cloexec(%s): 0x%.2x\n", (cloexec and "true" or "false"), flags))
			assert((flags == unix.FD_CLOEXEC) == cloexec)
		end
	end)
end))


debug.units.run"^iov.*" --> these are always safe to run
debug.units.run"^opts.*" --> ""
--debug.units.run"^io%..*"

return debug
