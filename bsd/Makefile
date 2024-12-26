KMOD=hookFrame
ARCH != echo $$(uname -m)

SRCS+=framework/module.c
SRCS+=framework/symbol_resolve.c
SRCS+=framework/hijack_operation.c
SRCS+=framework/dev_interface.c
SRCS+=arch/$(ARCH)/hijack_$(ARCH).c
SRCS+=vnode_if.h

.if $(ARCH) == "amd64"
SRCS+=arch/$(ARCH)/distorm/decoder.c
SRCS+=arch/$(ARCH)/distorm/distorm.c
SRCS+=arch/$(ARCH)/distorm/instructions.c
SRCS+=arch/$(ARCH)/distorm/insts.c
SRCS+=arch/$(ARCH)/distorm/mnemonics.c
SRCS+=arch/$(ARCH)/distorm/operands.c
SRCS+=arch/$(ARCH)/distorm/prefix.c
SRCS+=arch/$(ARCH)/distorm/textdefs.c
.endif

SRCS+=sample/replace_sys_open.c
SRCS+=sample/hook_fdrop.c

CFLAGS+=-I$(PWD)/framework -I$(PWD)/arch/$(ARCH) -D"_$(ARCH)_"
.include <bsd.kmod.mk>
