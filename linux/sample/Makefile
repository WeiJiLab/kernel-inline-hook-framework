ccflags-y := $(EXTRA_DEF) -I$(PWD)/../src -I$(PWD)/include -fno-pic -fno-stack-protector
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
	@echo "riscv	Linux, RISCV64"

arm64 arm x86 x86_64 powerpc riscv:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef vermagic
	$(call compile,$(MAKECMDGOALS),-D_ARCH_$(shell echo "$(MAKECMDGOALS)" | tr 'a-z' 'A-Z')_)
else
	@bash prevermagic.sh $(KDIR) "$(vermagic)"
	$(call compile,$(MAKECMDGOALS),-D_ARCH_$(shell echo "$(MAKECMDGOALS)" | tr 'a-z' 'A-Z')_)
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
endif

compile = $(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) KBUILD_MODPOST_WARN=1 KBUILD_EXTRA_SYMBOLS=$(KBUILD_EXTRA_SYMBOLS) EXTRA_DEF=$(2) -C $(KDIR) M=$(PWD) modules

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod|usyms|symversions)" | xargs rm -f
