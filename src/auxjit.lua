local loader = function(loader, ...)
	local function require_ffi()
		local chunk = string.dump((loadstring or load)("return"))
		return chunk:match"^\027LJ" and require"ffi" or nil
	end

	local ffi = require_ffi()
	local auxjit = {}

	auxjit.load = ffi and function (getcdef)
		local cdef, table = getcdef()
		local typename = assert(cdef:match("^%s*(struct%s+[%w_]+)"), "bad typename in module cdef")

		ffi.cdef(cdef)

		return ffi.cast(string.format("%s *", typename), table)
	end or function () return end

	return auxjit
end -- loader

return loader(loader, ...)
