# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1

include $(d)/../GNUmakefile


.PHONY: $(d)/check check

$(d)/check:
	@for V in 5.1 5.2 5.3; do \
		printf "Building $${V}... "; \
		if (cd $(@D) && ./regress.sh -r"$${V}" build >/dev/null 2>&1); then \
			printf "OK\n"; \
		else \
			printf "FAIL\n"; \
		fi; \
	done
	@cd $(@D); P=0; F=0; for T in ./[123456789]*.lua; do \
		if "./$$T" -B; then P=$$(($$P + 1)); else F=$$(($$F + 1)); fi; \
	done; \
	printf "PASS=%d FAIL=%d\n" "$$P" "$$F"; \
	test $$F -eq 0;

check: $(d)/check


.PHONY: $(d)/clean $(d)/clean~

$(d)/clean:
	$(RM) -fr $(@D)/.local

$(d)/clean~: $(d)/clean
	$(RM) -f $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
