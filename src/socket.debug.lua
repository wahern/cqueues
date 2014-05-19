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
-- iov_eoh consumes a multi-line MIME header at the beginning of the source
-- text. Returns the prefix length of the header. A return value greater
-- than #text means more text is necessary.
--
-- On error returns nil, error string, and error number.
--
local iov_eoh = debug.iov_eoh -- (text, eof)

local txt = "Foo: bar\n"
local n = assert(iov_eoh(txt, false))
assert(n > #txt)

local txt = "Foo: bar\n \n\tbaz"
local n = assert(iov_eoh(txt, true))
assert(n == #txt)

local txt = "Foo: bar\n\n"
local n = assert(iov_eoh(txt, false))
assert(n == #txt - 1)


--
-- iov_eob consumes data up and including the specified MIME boundary
-- marker. Returns the prefix length of the chunk. A return value greater
-- than #text means more text is necessary. 0 means the boundary was
-- not found.
--
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


--
-- iov_trimcr removes \r from \r\n pairs. If chomp is true, then only removes
-- \r from ending \r\n pair. Returns translated string.
--
local iov_trimcr = debug.iov_trimcr -- (text, chomp)

for _, txt in pairs{ "1\r\n2\r\n3\r\n", "\r\n\r" } do
	local gs = string.gsub(txt, "\r\n", "\n")
	assert(gs == iov_trimcr(txt, false), string.format("%s != %s", toviz(gs), toviz(txt)))
end


--
-- iov_trimcrlf removes \r from \r\n pairs. If chomp is true, then only
-- removes \r\n from end of string. Returns translated string.
--
local iov_trimcrlf = debug.iov_trimcrlf -- (text, chomp)

for _, txt in pairs{ "\r\n.\r\r\r\n", "\r\n\r\r\r", "\r\r.\n\n" } do
	local gs = string.gsub(txt, "\r?\n", "")
	assert(gs == iov_trimcrlf(txt, false), string.format("%s != %s", toviz(gs), toviz(txt)))
end

for _, txt in pairs{ "\r\n.\r\n", "\n", "\n\r\n\n" } do
	local gs = string.gsub(txt, "\r?\n$", "")
	assert(gs == iov_trimcrlf(txt, true), string.format("%s != %s", toviz(gs), toviz(txt)))
end


return debug
