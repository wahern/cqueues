#!/bin/sh
_=[[
	. "${0%%/*}/regress.sh"
	exec runlua "$0" "$@"
]]

require"regress".export".*"

local context = require"openssl.ssl.context"

local function exists(path)
	local fh = io.open(path, "r")

	if fh then
		fh:close()
		return true
	else
		return false
	end
end

-- return integer version of openssl(1) command-line tool at path
local function openssl_version(path)
	local fh = io.popen(string.format("%s version", path), "r")
	local ln = (fh and fh:read()) or ""

	if fh then
		fh:close()
	end

	local M, m, p

	if ln:match"LibreSSL" then
		p, M, m = 0, ln:match("(%d+)%.(%d+)")
	else
		M, m, p = ln:match("(%d+)%.(%d+)%.(%d+)")

	end

	if M then
		return (tonumber(M) * 268435456) + (tonumber(m) * 1048576) + (tonumber(p) * 4096)
	end
end

-- find most recent version of openssl(1) command-line tool
local function openssl_path()
	local paths = check(os.getenv"PATH", "no PATH in environment")
	local path = nil
	local version = 0

	for D in paths:gmatch("[^:]+") do
		local tmp_path = D .. "/openssl"
		local tmp_version = exists(tmp_path) and openssl_version(tmp_path)

		if tmp_version and tmp_version > version then
			info("found %s (%x)", tmp_path, tmp_version)
			path = tmp_path
			version = tmp_version
		end
	end

	return version > 0 and path
end

local function openssl_popen(path)
	local key, crt = genkey()
	local tmpname = os.tmpname()
	local tmpfile = check(io.open(tmpname, "w"))

	check(tmpfile:write(key:toPEM"private"))
	check(tmpfile:write(tostring(crt)))
	check(tmpfile:flush())
	tmpfile:close()

	local perl_main = [[
		use POSIX;
		use strict;

		my ($openssl, $key) = @ARGV;

		my $pid = fork;
		die "$!" unless defined $pid;

		# exec openssl in child
		exec $openssl, "s_server", "-quiet", "-dtls1", "-key", $key, "-cert", $key
			or die "$!" if $pid == 0;

		<STDIN>; # wait for EOF

		unlink $key;

		while ($pid != (my $rpid = waitpid($pid, WNOHANG))) {
			die "$!" if $rpid == -1;
			#print STDERR "killing $pid\n";
			kill 9, $pid;
			sleep 1;
		}

		#print STDERR "reaped $pid\n";

		1;

		EOF
	]]

	local perl_begin = ([[
		my @code;

		while (<STDIN>) {
			last if m/^\s+EOF\s+$/;
			push @code, $_;
		}

		eval join("", @code)
			or die $@;
	]]):gsub("%s+", " ")

	local function quote(txt)
		return string.format("'%s'", txt:gsub("'", "'\"'\"'"))
	end

	local perl_cmd = string.format("perl -e %s %s %s", quote(perl_begin), quote(path), quote(tmpname))

	local fh = check(io.popen(perl_cmd, "w"))
	fh:write(perl_main)
	fh:flush()

	cqueues.sleep(1) -- wait for server to begin listening

	return fh
end

local main = cqueues.new()

assert(main:wrap(function ()
	-- spin up DTLS server using openssl(1) command-line utility
	local fh = openssl_popen(check(openssl_path(), "no openssl command-line utility found"))

	-- create client socket
	local con = socket.connect{ host="localhost", port=4433, type=socket.SOCK_DGRAM };
	check(fileresult(con:starttls(context.new"DTLSv1", 3)))

	fh:close()
end):loop())

say"OK"

