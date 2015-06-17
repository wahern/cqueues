local loader = function(loader, ...)
	local function require_ffi()
		local chunk = string.dump((loadstring or load)("return"))
		return chunk:match"^\027LJ" and require"ffi" or nil
	end

	local ffi = require_ffi()
	local auxjit = {}

	auxjit.loadlib = ffi and function (cdef, modname)
		local path = assert(package.searchpath(modname, package.cpath))

print(cdef)
		ffi.cdef(cdef)

		return assert(ffi.load(path))
	end or function () return end

	auxjit.loadtable = ffi and function (cdef, table)
		local typename = assert(cdef:match("^%s*(struct%s+[%w_]+)"), "bad typename in module cdef")

		ffi.cdef(cdef)

		return ffi.cast(string.format("%s *", typename), table)
	end or function () return end

	return auxjit
end -- loader

return loader(loader, ...)
