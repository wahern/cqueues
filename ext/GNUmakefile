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

.INTERMEDIATE: liblua$(1)-openssl openssl$(1)

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

all: liblua5.1-openssl liblua5.2-openssl

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
	$$(DESTDIR)$(3)/openssl/cipher.lua

.INTERMEDIATE: liblua$(1)-openssl-install install$(1)

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

liblua$(1)-openssl-install install$(1): $$(MODS$(1)_$$(d))

.PHONY: liblua$(1)-openssl-uninstall uninstall$(1) uninstall

liblua$(1)-openssl-uninstall:
	$$(RM) -f $$(MODS$(1)_$(d))
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/x509
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/ssl
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl

uninstall$(1): liblua$(1)-openssl-uninstall

endef # INSTALL_$(d)

$(eval $(call INSTALL_$(d),5.1,$$(lua51cpath),$$(lua51path)))

$(eval $(call INSTALL_$(d),5.2,$$(lua52cpath),$$(lua52path)))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""

install: liblua5.1-openssl-install liblua5.2-openssl-install

uninstall: liblua5.1-openssl-uninstall liblua5.2-openssl-uninstall

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


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
