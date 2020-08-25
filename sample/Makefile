obj-m += hookFrameTest.o

hookFrameTest-y += module.o
hookFrameTest-y += hook_vfs_read.o
hookFrameTest-y += replace_vfs_open.o

PWD := $(shell pwd)

default:
	@echo "make TARGET KDIR=/path/to/kernel CROSS_COMPILE= vermagic="
	@echo
	@echo "Supported targets:"
	@echo "test-arm64	Linux, ARM"
	@echo "test-arm32	Linux, ARM"
	@echo

test-arm64:
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
	@bash aftvermagic.sh $(KDIR) "$(vermagic)" hookFrameTest
endif

test-arm32:
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

compile = $(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) EXTRA_CFLAGS="$(2) -I$(PWD)/include -fno-pic" -C $(KDIR) M=$(PWD) modules

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
