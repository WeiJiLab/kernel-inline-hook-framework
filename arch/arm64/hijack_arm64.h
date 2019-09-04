#ifndef _HOOK_ARM64_H_
#define _HOOK_ARM64_H_

#define HOOK_FUNC_TEMPLATE(s)  \
extern void hook_##s##_template(void);  \
asm (  \
    "hook_"#s"_template:\n\t"  \
    "ldr x0, [sp, #-0x8]\n\t"  \
    "b hook_"#s"\n\t"  \
  \
    #s"_code_space:\n\t"  \
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
);

#define GET_TAG_ADDERSS(s) \
({  \
    void *template; \
    __asm__ volatile ("ldr %0, =hook_"#s"_template\n\t":"=r"(template)); \
    template;  \
})

#define INSTRUCTION_SIZE 4
#define HIJACK_INST_NUM 5
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#endif