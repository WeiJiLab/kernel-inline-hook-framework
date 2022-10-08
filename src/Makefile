obj-m += hookFrame.o

hookFrame-y += framework/module.o
hookFrame-y += framework/hijack_operation.o
hookFrame-y += framework/stack_safety_check.o
hookFrame-y += framework/symbol_resolver.o
hookFrame-y += framework/write_map_page.o
hookFrame-y += framework/proc_interface.o
hookFrame-y += arch/$(ARCH)/hijack_$(ARCH).o
ifneq ($(findstring $(ARCH),"x86_64 x86"),)
hookFrame-y += arch/$(ARCH)/common.o
hookFrame-y += arch/$(ARCH)/distorm/decoder.o
hookFrame-y += arch/$(ARCH)/distorm/distorm.o
hookFrame-y += arch/$(ARCH)/distorm/instructions.o
hookFrame-y += arch/$(ARCH)/distorm/insts.o
hookFrame-y += arch/$(ARCH)/distorm/mnemonics.o
hookFrame-y += arch/$(ARCH)/distorm/operands.o
hookFrame-y += arch/$(ARCH)/distorm/prefix.o
hookFrame-y += arch/$(ARCH)/distorm/textdefs.o
endif

PWD := $(shell pwd)
default:
	@echo "make TARGET KDIR=/path/to/kernel CROSS_COMPILE= vermagic="
	@echo
	@echo "Supported targets:"
	@echo "arm64	Linux, ARM"
	@echo "arm	Linux, ARM"
	@echo "x86_64	Linux, X86_64"
	@echo "x86	Linux, X86"

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
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,arm64,-D_ARCH_ARM64_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrame
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
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,arm,-D_ARCH_ARM_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrame
endif

x86_64:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,x86_64,-D_ARCH_X86_64_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,x86_64,-D_ARCH_X86_64_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrame
endif

x86:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,x86,-D_ARCH_X86_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,x86,-D_ARCH_X86_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrame
endif

define compile
	$(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) EXTRA_CFLAGS="$(2) -I$(PWD) -I$(PWD)/arch/$(1) -fno-pic -fno-stack-protector" -C $(KDIR) M=$(PWD) modules
endef

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
