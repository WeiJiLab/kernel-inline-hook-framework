#ifndef _HOOK_RISCV_H_
#define _HOOK_RISCV_H_

#define HOOK_FUNC_TEMPLATE(s)  \
extern void hook_##s##_template(void);  \
asm (  \
    ".globl hook_"#s"_template\n\t"  \
    "hook_"#s"_template:\n\t"  \
    "ld    t1, 8(sp)\n\t" \
    "addi  sp, sp, 16\n\t" \
    "j     hook_"#s"\n\t"  \
  \
    ".globl "#s"_code_space\n\t"  \
    #s"_code_space:\n\t"  \
    ".word 0\n\t"  \
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
    ".word 0\n\t"  \
);

#define GET_TEMPLATE_ADDERSS(s) \
({  \
    void *template; \
    __asm__ volatile ("la %0, hook_"#s"_template\n\t":"=r"(template)); \
    template;  \
})

#define GET_CODESPACE_ADDERSS(s) \
({  \
    void *codespace; \
    __asm__ volatile ("la %0, "#s"_code_space\n\t":"=r"(codespace)); \
    codespace;  \
})

#define GET_HOOK_FUNC_ADDRESS(s) \
({  \
    void *hook_func; \
    __asm__ volatile ("la %0, hook_"#s"\n\t":"=r"(hook_func)); \
    hook_func;  \
})

#define HIJACK_SIZE 28
#define LONG_JMP_CODE_LEN 26
int fill_nop_for_target(void *, void *);
int fill_nop_for_code_space(void *, void *);
int init_arch(void);
#define HOOK_TARGET_OFFSET (0)
#define CODE_SPACE_OFFSET (0)
#endif
