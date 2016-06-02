#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]
require"regress".export".*"

--
-- Issue #71A -- After the addition of alerts, cqueue:loop waited indefinitely
-- on an empty queue when the original, more desirable behavior was that it
-- should immediately return.
--
-- Issue #71B -- cqueue:step did not clear an alert, causing the cqueue to
-- continually poll as ready even after calling cqueue:step.
--

local function check_71A()
	info"testing issue 71A"

	-- run loop from top-level so we're not testing the nested :step logic
	local grace = 3
	local fh = check(io.popen(string.format([[
		GRACE=%d
		run_and_wait() {
			. "${CQUEUES_SRCDIR}/regress/regress.sh" || exit 1;
			runlua - <<-EOF &
				require"regress".export".*"
				assert(cqueues.new():loop())
				io.stdout:write"OK\n"
			EOF
			PID="$!"
			sleep ${GRACE}
			set +e # disable strict errors
			kill -9 "${PID}" 2>&-
			wait "${PID}"
			RC="$?"
			printf "RC=%%d\n" "${RC}"
		}
		exec </dev/null
		run_and_wait &
	]], grace), "r"))

	check(cqueues.new():wrap(function ()
		local con = check(fileresult(socket.dup(fh)))
		local ln, why = fileresult(con:xread("*l", grace + 1))
		check(ln, "%s", why or "End of file")
		check(ln == "OK", "expected \"OK\", got \"%s\"", tostring(ln))
	end):loop())

	info"71A OK"
end

local function check_71B()
	info"testing 71B"

	local outer = cqueues.new()
	local inner = cqueues.new()
	local cv = condition.new()

	outer:wrap(function ()
		info"setting alert on inner loop"
		check(inner:alert())

		--
		-- NOTE: A kqueue descriptor will continue polling as
		-- readable until kevent(2) returns 0 events. As of
		-- 2016-06-01, cqueue:step does not iteratively call kevent.
		-- That may change in the future, but for now on BSDs code
		-- must :step twice for an alert to clear such that a queue
		-- stops polling as ready.
		--
		local count = 0
		local clear = false
		while not clear and count < 3 do
			count = count + 1

			info"stepping inner loop"
			check(inner:step())

			info"polling inner loop"
			cqueues.poll(inner, 0)
			local e1, e2 = cqueues.poll(inner, 0)
			clear = e1 ~= inner and e2 ~= inner
		end
		check(clear, "alert not cleared")
		info("alert cleared after %d steppings", count)

		cv:signal()
	end)

	outer:wrap(function ()
		check(cv:wait(3), "timeout before inner loop test completed")
	end)

	check(outer:loop())

	info"71B OK"
end

check_71A()
check_71B()
say"OK"
