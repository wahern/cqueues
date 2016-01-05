#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	runlua "$0" "$@"
	RC="$?"
	if [ ${RC} -eq 0 ]; then
		case ${VERBOSE} in
		0)
			;;
		1)
			printf "\n%s: OK\n" "${PROGNAME}"
			;;
		*)
			printf "%s: OK\n" "${PROGNAME}"
			;;
		esac
	fi
	exit ${RC}
]]
require"regress".export".*"

--
-- Issue #130 -- Segfault due to passing NULL cstack to cstack_isrunning from
-- condition variable __gc
--
-- cqueue_destroy only cleaned up threads on the polling queue, not the
-- pending queue. If a thread was waiting on a condition variable, but was
-- made pending for another reason (e.g. timeout or other event), then the
-- condition variable <-> controller association would still be installed,
-- holding a reference to the controller. If the controller was garbage
-- collected with the thread still on the pending queue and before the
-- condition variable was collected (as it could be if both were destroyed
-- in the same cycle, like when both survive until Lua VM destruction time),
-- then the condition variable destructor cond__gc would attempt to access a
-- pointer to a defunct controller object via the wakecb structure. In this
-- particular case, one of the results was a NULL pointer dereference.
--
-- The fix was to walk both the thread.polling _and_ thread.pending queues,
-- calling thread_del. thread_del breaks any wakecb associations.
--

-- stop GC to ensure everything destroyed on exit in same cycle
info"stopping GC"
collectgarbage"stop"


-- instantiate first so cond__gc invoked after cqueue__gc (only required for
-- 5.2 and 5.3).
local cv1 = check(condition.new())
local cv2 = check(condition.new())
local cq = cqueues.new()

local ready = false

cq:wrap(function()
	info"starting thread 1"

	ready = true

	-- one condvar to wake us; another to ensure we still
	-- have a wakecb installed
	info"thread 1 polling"
	cqueues.poll(cv1, cv2)
end)

check(cq:step(), "thread 1 failed to start")

cq:wrap(function()
	info"starting thread 2"

	-- put 1st thread in pending state
	info"putting thread 1 into pending state"
	check(ready, "thread 1 not ready")
	cv1:signal()

	-- short-circuit loop so 2nd thread is never run
	info"short-circuiting loop"
	error"oops"
end)


check(not cq:loop(), "loop was expected to fail")
