local require = require -- may be overloaded by regress.require
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

function regress.info(...)
	regress.say(...)
end -- info

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

function regress.require(modname)
	local ok, module = pcall(require, modname)

	regress.check(ok, "module %s required", modname)

	return module
end -- regress.require

function regress.genkey(type)
	local pkey = regress.require"openssl.pkey"
	local x509 = regress.require"openssl.x509"
	local name = regress.require"openssl.x509.name"
	local altname = regress.require"openssl.x509.altname"
	local key

	type = string.upper(type or "RSA")

	if type == "EC" then
		key = regress.check(pkey.new{ type = "EC",  curve = "prime192v1" })
	else
		key = regress.check(pkey.new{ type = type, bits = 1024 })
	end

	local dn = name.new()
	dn:add("C", "US")
	dn:add("ST", "California")
	dn:add("L", "San Francisco")
	dn:add("O", "Acme, Inc.")
	dn:add("CN", "acme.inc")

	local alt = altname.new()
	alt:add("DNS", "acme.inc")
	alt:add("DNS", "localhost")

	local crt = x509.new()
	crt:setVersion(3)
	crt:setSerial(47)
	crt:setSubject(dn)
	crt:setIssuer(crt:getSubject())
	crt:setSubjectAlt(alt)

	local issued, expires = crt:getLifetime()
	crt:setLifetime(issued, expires + 60)

	crt:setBasicConstraints{ CA = true, pathLen = 2 }
	crt:setBasicConstraintsCritical(true)

	crt:setPublicKey(key)
	crt:sign(key)

	return key, crt
end -- regress.genkey

return regress
