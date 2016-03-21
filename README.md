## API Documentation

Please refer to the PDF available at
<http://25thandclement.com/~william/projects/cqueues.pdf>


## Build Dependancies

The Makefile requires GNU Make. The source code should build with recent
GCC, clang, or Solaris SunPro compilers.

If you use your own Makefile, note that GCC and especially clang may emit
copious warnings about initializers and unused parameters. These warnings
are stupid. Use `-Wno-override-init` (GCC), `-Wno-initializer-overrides`
(clang) and `-Wno-unused` to quiet these. For other warnings, patches
welcome.

M4 and awk are required to generate `errno.c`. It relies on `mk/errno.list` to
enumerate the system error macro names. `mk/errno.list` is a small
POSIX-compatible shell script. By default it processes GCC's `-dM` macro list
(clang also supports this option). For SunPro it uses a slightly cruder
method.

Because the location of Lua include headers are unpredictable across
systems, the build system by default relies on `mk/luapath` to locate the
correct headers. `mk/luapath` uses various POSIX utilities. For more
information [see the luapath project page](http://25thandclement.com/~william/projects/luapath.html).
But see `LUA_APIS`, `LUA51_CPPFLAGS`, `LUA52_CPPFLAGS`, and
`LUA53_CPPFLAGS`, below.

`cqueues` should work on recent versions of Linux, OS X, Solaris, NetBSD,
FreeBSD, OpenBSD, and derivatives. The regression suite is run on all
supported platforms before rolling a release, and regularly during the
development. In the future support may be added for AIX and the AIX
`pollset` interface. Windows support is planned, though initially by relying
on BSD `select`.

## Build Overview

There is no separate `./configure` step at the moment. System introspection
occurs during compile time. However, the `configure` Make target can be used
to cache the build environment.


## Build Environment

### Lua APIs

`cqueues` targets the three latest Lua APIs---5.1, 5.2, and 5.3---and all
can be compiled simultaneously. Supported build targets are automatically
detected by default. To override API autodetection specify `LUA_APIS`. For
example,

```
$ make LUA_APIS="5.2 5.3"
```


### Toolchain Flags

All the common GNU-style compiler variables are supported, including `CC`,
`CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `SOFLAGS`, and `LIBS`. Note that you can
specify the path to both Lua 5.1, 5.2, and 5.3 include headers at the same
time in `CPPFLAGS`; the build system will work things out to ensure the
correct headers are loaded at compile-time. To specify them explicitly
provide

  - `LUA51_CPPFLAGS` - preprocessor flags for Lua 5.1
  - `LUA52_CPPFLAGS` - preprocessor flags for Lua 5.2
  - `LUA53_CPPFLAGS` - preprocessor flags for Lua 5.3

To completely override all internally-defined flags, specify the
`ALL_`-prefixed variant of any of the above. For example, specify
`ALL_CPPFLAGS` to override the built-in optimization and warning flags.
Note that object files are built using a command similar to

```
$ $(CC) $(ALL_LUA53_CPPFLAGS) $(ALL_CPPFLAGS)
```

where the Lua-specific flags remain separate from more general flags.


### Installation Paths

All the common GNU-style installation path variables are supported,
including `prefix`, `bindir`, `libdir`, `datadir`, `includedir`, and
`DESTDIR`. These additional path variables are also allowed:

  - `lua51path`  - install path for Lua 5.1 modules, e.g. `$(prefix)/share/lua/5.1`
  - `lua51cpath` - install path for Lua 5.1 C modules, e.g. `$(prefix)/lib/lua/5.1`
  - `lua52path`  - install path for Lua 5.2 modules, e.g. `$(prefix)/share/lua/5.2`
  - `lua52cpath` - install path for Lua 5.2 C modules, e.g. `$(prefix)/lib/lua/5.2`
  - `lua53path`  - install path for Lua 5.3 modules, e.g. `$(prefix)/share/lua/5.3`
  - `lua53cpath` - install path for Lua 5.3 C modules, e.g. `$(prefix)/lib/lua/5.3`


### Caching Environment

Invoking the `configure` target will cache the Make environment and reload
the variable values on subsequent invocations. Variables can be modified on
an individual basis after this.


## Build Targets

`cqueues` targets the Lua 5.1 (LuaJIT), 5.2, and 5.3 API. For various reasons
the build system is capable of building all three modules simultaneously in
a single Make invocation. Therefore, there are many seemingly superfluous
target names, either out of necessity or for convenience.


### Compile Targets

#### liblua5.1-cqueues

Build Lua 5.1 cqueues modules

#### liblua5.2-cqueues

Build Lua 5.2 cqueues modules

#### liblua5.3-cqueues

Build Lua 5.3 cqueues modules

#### all5.1

Synonym for liblua5.1-cqueues


#### all5.2

Synonym for liblua5.2-cqueues


#### all5.3

Synonym for liblua5.3-cqueues

#### all

Invokes one or more of the above according to the definition of `LUA_APIS`.


### Install Targets

#### liblua5.1-cqueues-install

Install Lua 5.1 cqueues modules

#### liblua5.2-cqueues-install

Install Lua 5.2 cqueues modules

#### liblua5.3-cqueues-install

Install Lua 5.3 cqueues modules

#### install5.1

Invokes liblua5.1-cqueues-install

#### install5.2

Invokes liblua5.2-cqueues-install

#### install5.3

Invokes liblua5.3-cqueues-install

#### install

Invokes one of more of the above install targets according to `LUA_APIS`.


### Uninstall Targets

#### liblua5.1-cqueues-uninstall

Uninstall Lua 5.1 cqueues modules

#### liblua5.2-cqueues-uninstall

Uninstall Lua 5.2 cqueues modules

#### liblua5.3-cqueues-uninstall

Uninstall Lua 5.3 cqueues modules

#### uninstall5.1

Invokes liblua5.1-cqueues-uninstall

#### uninstall5.2

Invokes liblua5.2-cqueues-uninstall

#### uninstall5.3

Invokes liblua5.3-cqueues-uninstall

#### uninstall

Invokes one or more of the above uninstall targets according to `LUA_APIS`.


### Other Targets

#### clean

rm binary targets, object files, debugging symbols, etc

#### clean~

clean + rm *~

#### debian

Build debian packages liblua5.1-cqueues and liblua5.2-cqueues using
the dpkg-buildpackage utility. The Make variables `DPKG_BUILDPACKAGE`
and `DPKG_BUILDPACKAGE_OPTIONS` can be used to manipulate this
process.


<!-- Markdeep: --><style class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script src="markdeep.min.js"></script><script src="https://casual-effects.com/markdeep/latest/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
