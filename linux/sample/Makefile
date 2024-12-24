obj-m += hookFrameTest.o

hookFrameTest-y += module.o
hookFrameTest-y += hook_vfs_read.o
hookFrameTest-y += hook_fuse_open.o
hookFrameTest-y += replace_vfs_open.o

PWD := $(shell pwd)
KBUILD_EXTRA_SYMBOLS = $(PWD)/../src/Module.symvers

default:
	@echo "make TARGET KDIR=/path/to/kernel CROSS_COMPILE= vermagic="
	@echo
	@echo "Supported targets:"
	@echo "arm64	Linux, ARM"
	@echo "arm32	Linux, ARM"
	@echo "x86_64	Linux, X86_64"
	@echo "x86	Linux, X86"
	@echo "powerpc	Linux, PPC64LE"

arm64:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,arm64,-D_ARCH_ARM64_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,arm64,-D_ARCH_ARM64_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
endif

arm:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,arm,-D_ARCH_ARM_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,arm,-D_ARCH_ARM_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
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
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
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
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
endif

powerpc:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,powerpc,-D_ARCH_POWERPC_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,powerpc,-D_ARCH_POWERPC_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrame
endif

compile = $(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) KBUILD_MODPOST_WARN=1 KBUILD_EXTRA_SYMBOLS=$(KBUILD_EXTRA_SYMBOLS) EXTRA_CFLAGS="$(2) -I$(PWD)/include -fno-pic" -C $(KDIR) M=$(PWD) modules

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
