local require = require -- may be overloaded by regress.require
local auxlib = require"cqueues.auxlib"

local regress = {
	cqueues = require"cqueues",
	socket = require"cqueues.socket",
	thread = require"cqueues.thread",
	errno = require"cqueues.errno",
	condition = require"cqueues.condition",
	auxlib = auxlib,
	assert = auxlib.assert,
	fileresult = auxlib.fileresult,
}

local emit_progname = os.getenv"PROGNAME" or "regress"
local emit_verbose = tonumber(os.getenv"VERBOSE" or 1)
local emit_info = {}
local emit_ll = 0

local function emit(fmt, ...)
	local msg = string.format(fmt, ...)

	for txt, nl in msg:gmatch("([^\n]*)(\n?)") do
		if emit_ll == 0 and #txt > 0 then
			io.stderr:write(emit_progname, ": ")
			emit_ll = #emit_progname + 2
		end

		io.stderr:write(txt, nl)

		if nl == "\n" then
			emit_ll = 0
		else
			emit_ll = emit_ll + #txt
		end
	end
end -- emit

local function emitln(fmt, ...)
	if emit_ll > 0 then
		emit"\n"
	end

	emit(fmt .. "\n", ...)
end -- emitln

local function emitinfo()
	for _, txt in ipairs(emit_info) do
		emitln("%s", txt)
	end
end -- emitinfo

function regress.say(...)
	emitln(...)
end -- say

function regress.panic(...)
	emitinfo()
	emitln(...)
	os.exit(false)
end -- panic

function regress.info(...)
	if emit_verbose > 1 then
		emitln(...)
	else
		emit_info[#emit_info + 1] = string.format(...)

		if emit_verbose > 0 then
			if emit_ll > 78 then
				emit"\n."
			else
				emit"."
			end
		end
	end
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


local function getsubtable(t, name, ...)
	name = name or false -- cannot be nil

	if not t[name] then
		t[name] = {}
	end

	if select('#', ...) > 0 then
		return getsubtable(t[name], ...)
	else
		return t[name]
	end
end -- getsubtable

function regress.newsslctx(protocol, accept, keytype)
	local context = regress.require"openssl.ssl.context"
	local ctx = context.new(protocol, accept)

	if keytype or keytype == nil then
		local key, crt = regress.genkey(keytype)

		ctx:setCertificate(crt)
		ctx:setPrivateKey(key)
	end

	return ctx
end -- require.newsslctx

local ctxcache = {}

function regress.getsslctx(protocol, accept, keytype)
	local keycache = getsubtable(ctxcache, protocol, accept)

	if keytype == nil then
		keytype = "RSA"
	end

	local ctx = keycache[keytype]

	if not ctx then
		ctx = regress.newsslctx(protocol, accept, keytype)
		keycache[keytype] = ctx
	end

	return ctx
end -- regress.getsslctx


return regress
