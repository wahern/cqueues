# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


#
# E N V I R O N M E N T  C O N F I G U R A T I O N
#
include $(d)/../GNUmakefile

include $(d)/lib/GNUmakefile


#
# C O M P I L A T I O N  F L A G S
#
OS_$(d) = $(shell $(d)/../mk/vendor.os)
LUAPATH_$(d) = $(shell env CC="$(CC)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" $(<D)/../mk/luapath -krxm3 -I$(DESTDIR)$(includedir) -I/usr/include -I/usr/local/include -P$(DESTDIR)$(bindir) -P$(bindir) -L$(DESTDIR)$(libdir) -L$(libdir) -v$(1) $(2))
VENDOR_$(d) = $(or $(CQUEUES_VENDOR),$(shell $(<D)/../mk/changelog author))
VERSION_$(d) = $(or $(CQUEUES_VERSION),$(shell $(<D)/../mk/changelog version))
COMMIT_$(d) = $(shell $(<D)/../mk/changelog commit)

CPPFLAGS_$(d) = $(CPPFLAGS_$(abspath $(@D)/../..)) -DLUA_COMPAT_APIINTCASTS
CFLAGS_$(d) = $(CFLAGS_$(abspath $(@D)/../..))
LDFLAGS_$(d) = $(LDFLAGS_$(abspath $(@D)/../..))
SOFLAGS_$(d) = $(SOFLAGS_$(abspath $(@D)/../..))

CPPFLAGS_$(d) += $(and $(VENDOR_$(<D)),-DCQUEUES_VENDOR='"$(VENDOR_$(<D))"')
CPPFLAGS_$(d) += $(and $(VERSION_$(<D)),-DCQUEUES_VERSION=$(VERSION_$(<D))L)
CPPFLAGS_$(d) += $(and $(COMMIT_$(<D)),-DCQUEUES_COMMIT='"$(COMMIT_$(<D))"')

LDFLAGS_$(d) += -L$(DESTDIR)$(libdir) -L$(libdir) -lssl -lcrypto -lpthread

# NetBSD, FreeBSD, OpenBSD (and presumably descendants) lack any libdl;
# dlopen, et al are part of libc.
ifneq ($(patsubst %BSD,BSD,$(OS_$(d))), BSD)
LDFLAGS_$(d) += -ldl
endif

# This only seems to be necessary on Linux. Darwin and OpenBSD lack a librt.
# On OpenBSD clock_gettime is part of libc. Others have librt, but linking
# it in is unnecessary.
ifeq ($(OS_$(d)), Linux)
LDFLAGS_$(d) += -lrt
endif

LDFLAGS_$(d) += -lm


#
# C O M P I L A T I O N  R U L E S
#
OBJS_$(d) = cqueues.o socket.o errno.o signal.o thread.o notify.o dns.o

# NOTE: M4 might fail so delay creating $@
$(d)/errno.c: $(d)/errno.c.m4
	cd $(@D) && $(M4) $< >| $@.tmp
	mv $@.tmp $@

define BUILD_$(d)

$$(d)/$(1)/cqueues.so: $$(addprefix $$(d)/$(1)/, $$(OBJS_$(d))) $$(d)/lib/libnonlua.a
	$$(CC) -o $$@ $$^ $$(SOFLAGS_$$(abspath $$(@D)/..)) $$(SOFLAGS) $$(LDFLAGS_$$(abspath $$(@D)/..)) $$(LDFLAGS)

$$(d)/$(1)/%.o: $$(d)/%.c $$(d)/cqueues.h $$(d)/compat52.h
	@test "$(1)" = "$$(call LUAPATH_$$(<D), $(1), version)" \
	|| (printf "%s\n" 'Unable to find Lua $(1) API headers (CPPFLAGS=$$(strip $$(call LUAPATH_$$(<D), $(1), cppflags) $(CPPFLAGS)))' >&2; false)
	$$(MKDIR) -p $$(@D)
	$$(CC) $$(CFLAGS_$$(<D)) $$(CFLAGS) $$(call LUAPATH_$$(<D), $(1), cppflags) $$(CPPFLAGS_$$(<D)) $$(CPPFLAGS) -c -o $$@ $$<

$$(d)/$(1)/cqueues.o: $$(d)/lib/llrb.h

$$(d)/$(1)/socket.o: $$(d)/lib/socket.h $$(d)/lib/dns.h $$(d)/lib/fifo.h

$$(d)/$(1)/errno.o: $$(d)/lib/socket.h $$(d)/lib/dns.h

$$(d)/$(1)/dns.o: $$(d)/lib/dns.h

$$(d)/$(1)/thread.o: $$(d)/lib/llrb.h

$$(d)/$(1)/notify.o: $$(d)/lib/notify.h

.SECONDARY: liblua$(1)-cqueues cqueues$(1) cqueues

liblua$(1)-cqueues cqueues$(1) cqueues: $$(d)/$(1)/cqueues.so

endef # BUILD_$(d)

$(eval $(call BUILD_$(d),5.1))

$(eval $(call BUILD_$(d),5.2))

$(eval $(call BUILD_$(d),5.3))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.SECONDARY: all all5.1 all5.2 all5.3

all5.1: liblua5.1-cqueues

all5.2: liblua5.2-cqueues

all5.3: liblua5.3-cqueues

all: all5.1 all5.2

endif


#
# I N S T A L L  &  U N I N S T A L L  R U L E S
#
define INSTALL_$(d)

LUAC$(1)_$(d) = $$(or $$(call LUAPATH_$(d), $(1), luac), true)

MODS$(1)_$(d) = \
	$$(DESTDIR)$(2)/_cqueues.so \
	$$(DESTDIR)$(3)/cqueues.lua \
	$$(DESTDIR)$(3)/cqueues/socket.lua \
	$$(DESTDIR)$(3)/cqueues/errno.lua \
	$$(DESTDIR)$(3)/cqueues/signal.lua \
	$$(DESTDIR)$(3)/cqueues/thread.lua \
	$$(DESTDIR)$(3)/cqueues/notify.lua \
	$$(DESTDIR)$(3)/cqueues/condition.lua \
	$$(DESTDIR)$(3)/cqueues/promise.lua \
	$$(DESTDIR)$(3)/cqueues/auxlib.lua \
	$$(DESTDIR)$(3)/cqueues/auxjit.lua \
	$$(DESTDIR)$(3)/cqueues/dns.lua \
	$$(DESTDIR)$(3)/cqueues/dns/resolver.lua \
	$$(DESTDIR)$(3)/cqueues/dns/config.lua \
	$$(DESTDIR)$(3)/cqueues/dns/hosts.lua \
	$$(DESTDIR)$(3)/cqueues/dns/hints.lua \
	$$(DESTDIR)$(3)/cqueues/dns/record.lua \
	$$(DESTDIR)$(3)/cqueues/dns/packet.lua \
	$$(DESTDIR)$(3)/cqueues/dns/resolvers.lua

.SECONDARY: liblua$(1)-cqueues-install cqueues$(1)-install

liblua$(1)-cqueues-install cqueues$(1)-install: $$(MODS$(1)_$$(d))

$$(DESTDIR)$(2)/_cqueues.so: $$(d)/$(1)/cqueues.so
	$$(MKDIR) -p $$(@D)
	cp -p $$< $$@

$$(DESTDIR)$(3)/%.lua: $$(d)/%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	cp -p $$< $$@

$$(DESTDIR)$(3)/cqueues/%.lua: $$(d)/%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	cp -p $$< $$@

$$(DESTDIR)$(3)/cqueues/dns/%.lua: $$(d)/dns.%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	cp -p $$< $$@

.PHONY: liblua$(1)-cqueues-uninstall cqueues$(1)-uninstall

liblua$(1)-cqueues-uninstall cqueues$(1)-uninstall:
	$$(RM) -f $$(MODS$(1)_$(d))
	-$$(RMDIR) $$(DESTDIR)$(3)/cqueues/dns
	-$$(RMDIR) $$(DESTDIR)$(3)/cqueues

endef # INSTALL_$(d)

$(eval $(call INSTALL_$(d),5.1,$$(lua51cpath),$$(lua51path)))

$(eval $(call INSTALL_$(d),5.2,$$(lua52cpath),$$(lua52path)))

$(eval $(call INSTALL_$(d),5.3,$$(lua53cpath),$$(lua53path)))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.SECONDARY: install5.1 install5.2 install5.3 install

install5.1: liblua5.1-cqueues-install

install5.2: liblua5.2-cqueues-install

install5.3: liblua5.3-cqueues-install

install: install5.1 install5.2

.PHONY: uninstall5.1 uninstall5.2 uninstall5.3 uninstall

uninstall5.1: liblua5.1-cqueues-uninstall

uninstall5.2: liblua5.2-cqueues-uninstall

uninstall5.3: liblua5.3-cqueues-uninstall

uninstall: uninstall5.1 uninstall5.2

endif


#
# C L E A N  R U L E S
#
.PHONY: $(d)/clean $(d)/clean~ clean clean~

$(d)/clean:
	rm -rf $(@D)/errno.c $(@D)/errno.c.tmp $(@D)/*.dSYM $(@D)/5.1 $(@D)/5.2 $(@D)/5.3

$(d)/clean~: $(d)/clean
	rm -f $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~


#
# H E L P  R U L E S
#
.PHONY: $(d)/help help

$(d)/help:
	@echo
	@echo "src/ targets:"
	@echo ""
	@echo "         all - build all binary targets"
	@echo "     cqueues - invokes cqueues5.1 and cqueues5.2"
	@echo "  cqueues5.1 - build 5.1/cqueues.so"
	@echo "  cqueues5.2 - build 5.2/cqueues.so"
	@echo "  cqueues5.3 - build 5.3/cqueues.so"
	@echo "     install - invokes install5.1 and install5.2"
	@echo "  install5.1 - install cqueues Lua 5.1 modules"
	@echo "  install5.2 - install cqueues Lua 5.2 modules"
	@echo "  install5.3 - install cqueues Lua 5.3 modules"
	@echo "   uninstall - invokes uninstall5.1 and uninstall5.2"
	@echo "uninstall5.1 - uninstall cqueues Lua 5.1 modules"
	@echo "uninstall5.2 - uninstall cqueues Lua 5.2 modules"
	@echo "uninstall5.3 - uninstall cqueues Lua 5.3 modules"
	@echo "       clean - rm binary targets, object files, debugging symbols, etc"
	@echo "      clean~ - clean + rm *~"
	@echo "        help - echo this help message"
	@echo ""
	@echo "Some important Make variables:"
	@echo ""
	@echo "    prefix - path to install root ($(value prefix))"
	@echo ' lua51path - install path for Lua 5.1 modules ($(value lua51path))'
	@echo 'lua51cpath - install path for Lua 5.1 C modules ($(value lua51cpath))'
	@echo ' lua52path - install path for Lua 5.2 modules ($(value lua52path))'
	@echo 'lua52cpath - install path for Lua 5.2 C modules ($(value lua52cpath))'
	@echo ' lua53path - install path for Lua 5.3 modules ($(value lua53path))'
	@echo 'lua53cpath - install path for Lua 5.3 C modules ($(value lua53cpath))'
	@echo ""
	@echo "(NOTE: all the common GNU-style paths are supported, including"
	@echo "prefix, bindir, libdir, datadir, includedir, and DESTDIR.)"
	@echo ""
	@echo "Report bugs to <william@25thandClement.com>"

help: $(d)/help


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
