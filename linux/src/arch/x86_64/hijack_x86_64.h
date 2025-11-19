#ifndef _HOOK_X86_64_H_
#define _HOOK_X86_64_H_

#define HOOK_FUNC_TEMPLATE(s)  \
extern void hook_##s##_template(void);  \
asm (  \
    ".globl hook_"#s"_template\n\t"  \
    "hook_"#s"_template:\n\t"  \
    "pop %rax\n\t" \
    "jmp hook_"#s"\n\t"  \
  \
    ".globl "#s"_code_space\n\t"  \
    #s"_code_space:\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
);

#define GET_TEMPLATE_ADDERSS(s) \
({  \
    void *template; \
    __asm__ volatile ("mov $hook_"#s"_template, %0\n\t":"=r"(template)); \
    template;  \
})

#define GET_CODESPACE_ADDERSS(s) \
({  \
    void *codespace; \
    __asm__ volatile ("mov $"#s"_code_space, %0\n\t":"=r"(codespace)); \
    codespace;  \
})

#define GET_HOOK_FUNC_ADDRESS(s) \
({  \
    void *hook_func; \
    __asm__ volatile ("mov $hook_"#s", %0\n\t":"=r"(hook_func)); \
    hook_func; \
})

#define HIJACK_SIZE 24
#define LONG_JMP_CODE_LEN 14
int fill_nop_for_target(void *, void *);
int fill_nop_for_code_space(void *, void *);
int init_arch(void);
#define HOOK_TARGET_OFFSET (0)
#define CODE_SPACE_OFFSET (0)
#define MAX_INSTRUCTIONS 20
#endif