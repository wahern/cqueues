local name = require"_openssl.x509.name"

name.interpose("__tostring", function (self)
	local t = { }

	for k, v in pairs(self) do
		t[#t + 1] = k .. "=" .. v
	end

	return table.concat(t, ", ")
end)

return name
