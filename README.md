## API Documentation

Please refer to the PDF available at
<http://25thandclement.com/~william/projects/cqueues.pdf>


## Build Dependancies

The Makefile requires GNU Make. The source code should build with recent
GCC, clang, or Solaris SunPro compilers.

If you use your own Makefile, note that GCC and especially clang may emit
copious warnings about initializers and unused parameters. These warnings
are stupid. Use -Wno-override-init (GCC), -Wno-initializer-overrides (clang)
and -Wno-unused to quiet these. For other warnings, patches welcome.

M4 and awk are required to generate errno.c. It relies on mk/errno.list to
enumerate the system error macro names. mk/errno.list is a small
POSIX-compatible shell script. By default it processes GCC's -dM macro list
(clang also supports this option). For SunPro it uses a slightly cruder
method.

Because the location of Lua 5.2 and LuaJIT include headers are completely
random across systems, the build system relies on mk/luapath to locate the
correct headers, including selecting the correct headers at compile-time
when conflicting headers are encountered. mk/luapath uses various POSIX
utilities. For more information, see
<http://25thandclement.com/~william/projects/luapath.html>

cqueues should work (plus or minus a few tweaks) on recent versions of
Linux, OS X, Solaris, NetBSD, FreeBSD, OpenBSD, and derivatives. The only
other possible candidate is AIX, if and when support for AIX's pollset
interface is added to the embedded "kpoll" library.


## Build Overview

There is no separate ./configure step. System introspection occurs during
compile-time. However, the `configure' Make target can be used to cache the
build environment.


## Build Environment

All the common GNU-style installation path variables are supported,
including prefix, bindir, libdir, datadir, includedir, and DESTDIR. These
additional path variables are also allowed:

  - lua51path  - install path for Lua 5.1 modules, e.g. $(prefix)/share/lua/5.1
  - lua51cpath - install path for Lua 5.1 C modules, e.g. $(prefix)/lib/lua/5.1
  - lua52path  - install path for Lua 5.2 modules, e.g. $(prefix)/share/lua/5.2
  - lua52cpath - install path for Lua 5.2 C modules, e.g. $(prefix)/lib/lua/5.2
  - lua53path  - install path for Lua 5.3 modules, e.g. $(prefix)/share/lua/5.3
  - lua53cpath - install path for Lua 5.3 C modules, e.g. $(prefix)/lib/lua/5.3

All the common GNU-style compiler variables are supported, including CC,
CPPFLAGS, CFLAGS, LDFLAGS, and SOFLAGS. Note that you can specify the path
to both Lua 5.1, 5.2, and 5.3 include headers at the same time in CPPFLAGS;
the build system will work things out to ensure the correct headers are
loaded at compile-time.

Invoking the `configure' target will cache the Make environment and reload
the variable values on subsequent invocations. Variables can be modified on
an individual basis after this.


## Build Targets

cqueues targets both the Lua 5.2 and Lua 5.1 (LuaJIT) API. For various
reasons the build system is capable of building both 5.1 and 5.2 modules
simultaneously in a single Make invocation. Therefore, there are many
seemingly superfluous target names, either out of necessity or for
convenience.


### liblua5.1-cqueues

Build Lua 5.1 cqueues modules


### liblua5.2-cqueues

Build Lua 5.2 cqueues modules


### liblua5.3-cqueues

Build Lua 5.3 cqueues modules


### liblua5.1-cqueues-install

Install Lua 5.1 cqueues modules


### liblua5.2-cqueues-install

Install Lua 5.2 cqueues modules


### liblua5.3-cqueues-install

Install Lua 5.3 cqueues modules


### liblua5.1-cqueues-uninstall

Uninstall Lua 5.1 cqueues modules


### liblua5.2-cqueues-uninstall

Uninstall Lua 5.2 cqueues modules


### liblua5.3-cqueues-uninstall

Uninstall Lua 5.3 cqueues modules


### cqueues5.1

Synonym for liblua5.1-cqueues


### cqueues5.2

Synonym for liblua5.2-cqueues


### cqueues5.3

Synonym for liblua5.2-cqueues


### cqueues

Invokes cqueues5.1 and cqueues5.2


### install5.1

Invokes liblua5.1-cqueues-install


### install5.2

Invokes liblua5.2-cqueues-install


### install5.3

Invokes liblua5.3-cqueues-install


### uninstall5.1

Invokes liblua5.1-cqueues-uninstall


### uninstall5.2

Invokes liblua5.2-cqueues-uninstall


### uninstall5.3

Invokes liblua5.3-cqueues-uninstall


### install

Invokes install5.1 and install5.2


### uninstall

Invokes uninstall5.1 and uninstall5.2


### all5.1

Build all Lua 5.1 binary targets


### all5.2

Build all Lua 5.2 binary targets


### all5.3

Build all Lua 5.3 binary targets


### all

Build all binary targets (the default)


### clean

rm binary targets, object files, debugging symbols, etc


### clean~

clean + rm *~


### debian

Build debian packages liblua5.1-cqueues and liblua5.2-cqueues using
the dpkg-buildpackage utility. The Make variables `DPKG_BUILDPACKAGE`
and `DPKG_BUILDPACKAGE_OPTIONS` can be used to manipulate this
process.
