package = "cqueues"
version = "20260715.55-1"
source = {
	url = "https://github.com/scossu/cqueues/archive/refs/tags/20260715.tar.gz";
	md5 = "67646b3a632a367ff6109f2178ae291e";
	dir = "cqueues-20260715";
}
description = {
	summary = "Continuation Queues: Embeddable asynchronous networking, threading, and notification framework for Lua on Unix.";
	homepage = "http://25thandclement.com/~william/projects/cqueues.html";
	license = "MIT/X11";
	maintainer = "Daurnimator <quae@daurnimator.com>";
}
supported_platforms = {
	"linux";
	"bsd";
	"solaris";
}
dependencies = {
	"lua == 5.5";
}
external_dependencies = {
	OPENSSL = {
		header = "openssl/ssl.h";
		library = "ssl";
	};
	CRYPTO = {
		header = "openssl/crypto.h";
		library = "crypto";
	};
}
build = {
	type = "make";
	makefile = "GNUmakefile";

	build_target = "all5.5";
	build_variables = {
		CPPFLAGS= '-I"$(OPENSSL_INCDIR)" -I"$(CRYPTO_INCDIR)"';
		CFLAGS = '$(CFLAGS)';
		LDFLAGS = '$(LIBFLAG) -L"$(OPENSSL_LIBDIR)" -L"$(CRYPTO_LIBDIR)"';
		bindir = "$(LUA_BINDIR)";
		includedir = "$(LUA_INCDIR)";
		libdir = "$(LUA_LIBDIR)";
	};

	install_target = "install5.5";
	install_variables = {
		prefix = "$(PREFIX)";
		lua55cpath = "$(LIBDIR)";
		lua55path = "$(LUADIR)";
		bindir = "$(BINDIR)";
	};
}
