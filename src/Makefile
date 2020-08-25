obj-m += hookFrame.o

hookFrame-y += framework/module.o
hookFrame-y += framework/hijack_operation.o
hookFrame-y += framework/stack_safety_check.o
hookFrame-y += framework/symbol_resolver.o
hookFrame-y += framework/write_map_page.o
hookFrame-y += framework/proc_interface.o
ifeq ($(ARCH), arm64)
hookFrame-y += arch/arm64/hijack_arm64.o
endif
ifeq ($(ARCH), arm)
hookFrame-y += arch/arm/hijack_arm.o
endif

PWD := $(shell pwd)
default:
	@echo "make TARGET KDIR=/path/to/kernel CROSS_COMPILE= vermagic="
	@echo
	@echo "Supported targets:"
	@echo "arm64	Linux, ARM"
	@echo "arm	Linux, ARM"
	@echo

arm64:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef CROSS_COMPILE
	@echo "Must provide CROSS_COMPILE!"
	@exit 1
endif
ifndef vermagic
	$(call compile,arm64,-D_ARCH_ARM64_)
else
	@bash prevermagic.sh $(KDIR) $(vermagic)
	$(call compile,arm64,-D_ARCH_ARM64_)
	@bash aftvermagic.sh $(KDIR) $(vermagic) hookFrame
endif

arm:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef CROSS_COMPILE
	@echo "Must provide CROSS_COMPILE!"
	@exit 1
endif
ifndef vermagic
	$(call compile,arm,-D_ARCH_ARM_)
else
	@bash prevermagic.sh $(KDIR) $(vermagic)
	$(call compile,arm,-D_ARCH_ARM_)
	@bash aftvermagic.sh $(KDIR) $(vermagic) hookFrame
endif

define compile
	$(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) EXTRA_CFLAGS="$(2) -I$(PWD) -I$(PWD)/arch/$(1) -fno-pic" -C $(KDIR) M=$(PWD) modules
endef

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
