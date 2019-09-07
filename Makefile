obj-m += secEnhance.o

secEnhance-y += framework/module.o
secEnhance-y += framework/hijack_operation.o
secEnhance-y += framework/stack_safety_check.o
secEnhance-y += framework/symbol_resolver.o
secEnhance-y += framework/write_map_page.o
secEnhance-y += framework/proc_interface.o
ifeq ($(ARCH), arm64)
secEnhance-y += arch/arm64/hijack_arm64.o
endif
ifeq ($(ARCH), arm)
secEnhance-y += arch/arm/hijack_arm.o
endif

PWD := $(shell pwd)
  
default:
	@echo "make TARGET KDIR=/path/to/kernel"
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
	export ARCH=arm64
	$(MAKE) ARCH=arm64 EXTRA_CFLAGS="-D_ARCH_ARM64_ -I$(PWD) -I$(PWD)/arch/arm64 -fno-pic" -C $(KDIR) M=$(PWD) modules

arm:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	export ARCH=arm
	$(MAKE) ARCH=arm EXTRA_CFLAGS="-D_ARCH_ARM_ -I$(PWD) -I$(PWD)/arch/arm -fno-pic" -C $(KDIR) M=$(PWD) modules

clean:
	find ./ -regextype posix-extended -regex ".*\.(ko|o|mod.c|order|symvers|d|cmd|mod)" | xargs rm -f
