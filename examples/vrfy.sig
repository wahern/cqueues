#!/usr/local/lua52/bin/lua
--
-- Example public-key signature verification.
--

local pubkey = require"openssl.pubkey"
local digest = require"openssl.digest"

-- generate a public/private key pair
local key = pubkey.new{ type = "EC", curve = "prime192v1" }

-- digest our message using an appropriate digest ("ecdsa-with-SHA1" for EC;
-- "dss1" for DSA; and "sha1", "sha256", etc for RSA).
local data = digest.new"ecdsa-with-SHA1"
data:update(... or "hello world")

-- generate a signature for our data
local sig = key:sign(data)

-- to prove verification works, instantiate a new object holding just
-- the public key
local pub = pubkey.new(key:toPEM"public")

-- a utility routine to output our signature
local function tohex(b)
	local x = ""
	for i = 1, #b do
		x = x .. string.format("%.2x", string.byte(b, i))
	end
	return x
end

print("okay", pub:verify(sig, data))
print("type", pub:type())
print("sig", tohex(sig))
