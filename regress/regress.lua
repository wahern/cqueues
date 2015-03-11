local auxlib = require"cqueues.auxlib"

local regress = {
	cqueues = require"cqueues",
	socket = require"cqueues.socket",
	thread = require"cqueues.thread",
	errno = require"cqueues.errno",
	auxlib = auxlib,
	assert = auxlib.assert,
	fileresult = auxlib.fileresult,
}

function regress.say(fmt, ...)
	io.stderr:write(os.getenv"PROGNAME" or "regress", ": ", string.format(fmt, ...), "\n")
end -- say

function regress.panic(...)
	regress.say(...)
	os.exit(false)
end -- panic

function regress.check(v, ...)
	if v then
		return v, ...
	else
		regress.panic(...)
	end
end -- check

function regress.export(...)
	for _, pat in ipairs{ ... } do
		for k, v in pairs(regress) do
			if string.match(k, pat) then
				_G[k] = v
			end
		end
	end

	return regress
end -- export

return regress
