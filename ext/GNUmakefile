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


#
# C O M P I L A T I O N  F L A G S
#
OS_$(d) = $(shell $(d)/../mk/vendor.os)
CC_$(d) = $(shell $(d)/../mk/vendor.cc)
LUAPATH_$(d) = $(shell env CC="$(CC)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" $(<D)/../mk/lua.path -krxm3 -I$(DESTDIR)$(includedir) -I/usr/include -I/usr/local/include -P$(DESTDIR)$(bindir) -P$(bindir) -L$(DESTDIR)$(libdir) -L$(libdir) -v$(1) $(2))

CPPFLAGS_$(d) = $(CPPFLAGS_$(abspath $(@D)/../..))
CFLAGS_$(d) = $(CFLAGS_$(abspath $(@D)/../..))
LDFLAGS_$(d) = $(LDFLAGS_$(abspath $(@D)/../..))
SOFLAGS_$(d) = $(SOFLAGS_$(abspath $(@D)/../..))

ifeq ($(CC_$(d)), sunpro)
CPPFLAGS_$(d) += -DOPENSSL_NO_EC
endif

LDFLAGS_$(d) += -lssl -lcrypto

#
# C O M P I L A T I O N  R U L E S
#

define BUILD_$(d)

.SECONDARY: liblua$(1)-openssl openssl$(1)

$$(d)/$(1)/openssl.so: $$(d)/$(1)/openssl.o
	$$(CC) -o $$@ $$^ $$(SOFLAGS_$$(abspath $$(@D)/..)) $$(SOFLAGS) $$(LDFLAGS_$$(abspath $$(@D)/..)) $$(LDFLAGS)

$$(d)/$(1)/openssl.o: $$(d)/openssl.c $$(d)/compat52.h
	test "$$(notdir $$(@D))" = "$$(call LUAPATH_$$(<D), $$(notdir $$(@D)), version)"
	$$(MKDIR) -p $$(@D)
	$$(CC) $$(CFLAGS_$$(<D)) $$(CFLAGS) $$(call LUAPATH_$$(<D), $$(notdir $$(@D)), cppflags) $$(CPPFLAGS_$$(<D)) $$(CPPFLAGS) -c -o $$@ $$<

liblua$(1)-openssl openssl$(1): $$(d)/$(1)/openssl.so

endef # BUILD_$(d)

$(eval $(call BUILD_$(d),5.1))

$(eval $(call BUILD_$(d),5.2))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.SECONDARY: all5.1 all5.2 all

all5.1: liblua5.1-openssl

all5.2: liblua5.2-openssl

all: all5.1 all5.2

endif


#
# I N S T A L L  &  U N I N S T A L L  R U L E S
#
define INSTALL_$(d)

LUAC$(1)_$(d) = $$(or $$(call LUAPATH_$(d), $(1), luac), true)

MODS$(1)_$(d) = \
	$$(DESTDIR)$(2)/_openssl.so \
	$$(DESTDIR)$(3)/openssl/bignum.lua \
	$$(DESTDIR)$(3)/openssl/pubkey.lua \
	$$(DESTDIR)$(3)/openssl/x509.lua \
	$$(DESTDIR)$(3)/openssl/x509/name.lua \
	$$(DESTDIR)$(3)/openssl/x509/altname.lua \
	$$(DESTDIR)$(3)/openssl/x509/chain.lua \
	$$(DESTDIR)$(3)/openssl/x509/store.lua \
	$$(DESTDIR)$(3)/openssl/ssl/context.lua \
	$$(DESTDIR)$(3)/openssl/ssl.lua \
	$$(DESTDIR)$(3)/openssl/digest.lua \
	$$(DESTDIR)$(3)/openssl/hmac.lua \
	$$(DESTDIR)$(3)/openssl/cipher.lua \
	$$(DESTDIR)$(3)/openssl/rand.lua

.SECONDARY: liblua$(1)-openssl-install openssl$(1)-install

$$(DESTDIR)$(2)/_openssl.so: $$(d)/$(1)/openssl.so
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/%.lua: $$(d)/openssl.%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/x509/%.lua: $$(d)/openssl.x509.%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/ssl/%.lua: $$(d)/openssl.ssl.%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/ssl/%.lua: $$(d)/openssl.ssl.%.lua
	$$(LUAC$(1)_$(d)) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

liblua$(1)-openssl-install openssl$(1)-install: $$(MODS$(1)_$$(d))

.PHONY: liblua$(1)-openssl-uninstall openssl$(1)-uninstall

liblua$(1)-openssl-uninstall openssl$(1)-uninstall:
	$$(RM) -f $$(MODS$(1)_$(d))
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/x509
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/ssl
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl

endef # INSTALL_$(d)

$(eval $(call INSTALL_$(d),5.1,$$(lua51cpath),$$(lua51path)))

$(eval $(call INSTALL_$(d),5.2,$$(lua52cpath),$$(lua52path)))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.SECONDARY: install5.1 install5.2 install

install5.1: liblua5.1-openssl-install

install5.2: liblua5.2-openssl-install

install: install5.1 install5.2

.PHONY: uninstall5.1 uninstall5.2 uninstall

uninstall5.1: liblua5.1-openssl-uninstall

uninstall5.2: liblua5.2-openssl-uninstall

uninstall: uninstall5.1 uninstall5.2

endif


#
# C L E A N  R U L E S
#
.PHONY: $(d)/clean $(d)/clean~ clean clean~

$(d)/clean:
	$(RM) -fr $(@D)/*.so $(@D)/*.o $(@D)/*.dSYM $(@D)/5.1 $(@D)/5.2

$(d)/clean~: $(d)/clean
	$(RM) -f $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~


#
# H E L P  R U L E S
#
.PHONY: $(d)/help help

$(d)/help:
	@echo
	@echo "ext/ targets:"
	@echo ""
	@echo "    all      - build all binary targets"
	@echo "openssl      - invokes openssl5.1 and openssl5.2"
	@echo "openssl5.1   - build 5.1/openssl.so"
	@echo "openssl5.2   - build 5.2/openssl.so"
	@echo "install      - invokes install5.1 and install5.2"
	@echo "install5.1   - install openssl Lua 5.1 modules"
	@echo "install5.2   - install openssl Lua 5.2 modules"
	@echo "uninstall    - invokes uninstall5.1 and uninstall5.2"
	@echo "uninstall5.1 - uninstall openssl Lua 5.1 modules"
	@echo "uninstall5.2 - uninstall openssl Lua 5.2 modules"
	@echo "  clean      - rm binary targets, object files, debugging symbols, etc"
	@echo " clean~      - clean + rm *~"
	@echo "   help      - echo this help message"
	@echo ""
	@echo "Some important Make variables:"
	@echo ""
	@echo "    prefix - path to install root"
	@echo ' lua51path - install path for Lua 5.1 modules ($$(lua51path))'
	@echo 'lua51cpath - install path for Lua 5.1 C modules ($$(lua51cpath))'
	@echo ' lua52path - install path for Lua 5.1 modules ($$(lua51path))'
	@echo 'lua52cpath - install path for Lua 5.1 C modules ($$(lua51cpath))'
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
