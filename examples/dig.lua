#!/usr/bin/env lua

local cqueues = require"cqueues"
local resolver = require"cqueues.dns.resolver"
local getopt = loadfile"getopt.lua"()

local usage = string.gsub([[
	dig -rsh [name] [type]
	  -r  recursive lookup beginning from root nameservers
	  -s  smart resolve NS, MX, etc to A records if not present
	  -h  print this usage message

	Report bugs to <william@25thandClement.com>
]], "^[\t\n]", ""):gsub("\n[\t]", "\n")

local args = {}
local opts = {}

for optnam, optval in getopt("rsh", ...) do
	if optnam then
		if optnam == "r" then
			opts.r = true
		elseif optnam == "s" then
			opts.s = true
		elseif optnam == "h" then
			io.stdout:write(usage)
			os.exit()
		else
			if optnam == "?" then
				io.stderr:write("invalid option: " .. optval .. "\n")
			end

			io.stderr:write(usage)
			os.exit(false)
		end
	else
		args[#args + 1] = optval
	end
end

local name = args[1] or "google.com"
local type = args[2] or "A"

assert(cqueues.new():wrap(function()
	local init = (opts.r and resolver.root) or resolver.stub
	local res = init{ smart = opts.s }

	print(tostring(assert(res:query(name, type))))

	local st = res:stat()

	print(string.format(";; queries:  %d", st.queries))
	print(string.format(";; udp sent: %d in %d bytes", st.udp.sent.count, st.udp.sent.bytes))
	print(string.format(";; udp rcvd: %d in %d bytes", st.udp.rcvd.count, st.udp.rcvd.bytes))
	print(string.format(";; tcp sent: %d in %d bytes", st.tcp.sent.count, st.tcp.sent.bytes))
	print(string.format(";; tcp rcvd: %d in %d bytes", st.tcp.rcvd.count, st.tcp.rcvd.bytes))
end):loop())

