obj-m += hookFrameTest.o

hookFrameTest-y += module.o
hookFrameTest-y += hook_vfs_read.o
hookFrameTest-y += replace_vfs_open.o

PWD := $(shell pwd)

default:
	@echo "make TARGET KDIR=/path/to/kernel" CROSS_COMPILE=
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
	$(call compile,arm64,-D_ARCH_ARM64_)

test-arm32:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
ifndef CROSS_COMPILE
	@echo "Must provide CROSS_COMPILE!"
	@exit 1
endif
	$(call compile,arm,-D_ARCH_ARM_)

compile = $(MAKE) ARCH=$(1) CROSS_COMPILE=$(CROSS_COMPILE) EXTRA_CFLAGS="$(2) -I$(PWD)/include -fno-pic" -C $(KDIR) M=$(PWD) modules

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
