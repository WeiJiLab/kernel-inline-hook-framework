#ifndef _HOOK_ARM64_H_
#define _HOOK_ARM64_H_

#define HOOK_FUNC_TEMPLATE(s)  \
extern void hook_##s##_template(void);  \
asm (  \
    ".globl hook_"#s"_template\n\t"  \
    "hook_"#s"_template:\n\t"  \
    "ldp x1, x0, [sp], #0x20\n\t" \
    "b hook_"#s"\n\t"  \
  \
    ".globl "#s"_code_space\n\t"  \
    #s"_code_space:\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
    ".word 0\n\t"  \
);

#define GET_TEMPLATE_ADDERSS(s) \
({  \
    void *template; \
    __asm__ volatile ("ldr %0, =hook_"#s"_template\n\t":"=r"(template)); \
    template;  \
})

#define GET_CODESPACE_ADDERSS(s) \
({  \
    void *codespace; \
    __asm__ volatile ("ldr %0, ="#s"_code_space\n\t":"=r"(codespace)); \
    codespace;  \
})

#define INSTRUCTION_SIZE 4
#define HIJACK_INST_NUM 6
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#endif