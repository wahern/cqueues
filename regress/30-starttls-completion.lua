#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
--
-- Originally socket:starttls did not poll waiting for handshake completion,
-- but instead simply placed the socket into TLS handshake mode and
-- immediately returned. As part of a larger refactoring to improve the
-- consistency of timeouts across the API, socket:starttls was changed to
-- accept a timeout parameter and to poll for completion before returning.
-- An explicit timeout of 0 seconds is necessary to return immediately.
--
-- However, early TLS example code called socket:starttls outside of any
-- event loop. So as to not break such code, if no timeout was provided
-- socket:starttls attempted to detect whether it was running inside an
-- event loop, and if not exhibited the original behavior of returning
-- immediately rather than polling indefinitely.
--
-- Since then, cqueues.poll has become capable of polling outside of an
-- event loop, albeit with the side-effect of blocking the application. To
-- improve consistency the backward's compatibility behavior has been
-- removed. socket:starttls now unconditionally polls for completion of the
-- handshake, up to any specified timeout.
--
require"regress".export".*"

local so = socket.connect("google.com", 443)
local ok, why = auxlib.fileresult(so:starttls())
check(ok, "STARTTLS failed: %s", why)
local ssl = check(so:checktls(), "no SSL object")
local crt = ssl:getPeerCertificate()
check(crt ~= nil, "bug not fixed")
say("OK")
