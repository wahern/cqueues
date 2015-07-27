#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

--
-- Acquire reference to internal openssl loader so we can reinvoke to
-- trigger the bug. The bug is that ex_newstate overwrites the registry
-- index where we stored our exdata state object from a previous invocation
-- of ex_newstate, causing it to be garbage collected.
--
-- When the state object is garbage collected, it invalidates all the
-- outstanding data attached to any extant object. The state object is an
-- interpreter-scoped singleton which should persist for the lifetime of the
-- Lua interpreter. Garbage collection is supposed to signal that the Lua
-- interpreter is being destroyed, and any data belonging to that
-- interpreter and attached to OpenSSL objects is invalid. (NB: The parent
-- application and any OpenSSL objects created from the interpreter can
-- persist after our Lua interpreter. For example in a multithreaded
-- application. Likewise, there can be multiple interpreters, each of which
-- must have its own exdata state.)
--
-- Because ex_newdata is run from initall, and initall is invoked whenever
-- any openssl submodule is loaded, this bug can be triggered by loading a
-- new submodule after installing exdata. Or, as here, it can be triggered
-- by explicitly reinvoking the loader for a submodule.
--
check(package.searchpath, "package.searchpath not defined")

local file, why = package.searchpath("_openssl", package.cpath)
check(file, "%s", why)
local reinit = check(package.loadlib(file, "luaopen__openssl_compat"))

local function ticklebug()
	reinit()

	for i=1,2 do
		collectgarbage"collect"
	end
end

--
-- Run our test. We don't have a way to force failure with versions of the
-- openssl module that have been fixed.
--
local main = check(cqueues.new())

check(main:wrap(function ()
	local alpn_attempts, alpn_issued = 0, 0
	local cli_ctx, srv_ctx

	cli_ctx = getsslctx("TLSv1", false, false)
	check(cli_ctx.setAlpnProtos, "ALPN support not available")
	cli_ctx:setAlpnProtos{ "http2.0", "http" }

	srv_ctx = getsslctx("TLSv1", true)
	srv_ctx:setAlpnSelect(function (ssl, list, ...)
		info("onAlpnSelect: %s", table.concat(list, " "))

		alpn_issued = alpn_issued + 1

		return list[1]
	end)

	for i=1,100 do
		local srv, cli = check(socket.pair(socket.SOCK_STREAM))

		check(main:wrap(function ()
			check(cli:starttls(cli_ctx))
		end))

		check(srv:starttls(srv_ctx))
		alpn_attempts = alpn_attempts + 1

		ticklebug()
	end

	info("%d ALPN callbacks issued in %d SSL connections", alpn_issued, alpn_attempts)
	check(alpn_attempts == alpn_issued, "wrong number of ALPN callbacks")
end))

check(main:loop())

say"OK"
