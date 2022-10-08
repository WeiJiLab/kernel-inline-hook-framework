#ifndef _HOOK_X86_H_
#define _HOOK_X86_H_

#define HOOK_FUNC_TEMPLATE(s)  \
extern void hook_##s##_template(void);  \
asm (  \
    ".globl hook_"#s"_template\n\t"  \
    "hook_"#s"_template:\n\t"  \
    "pop %eax\n\t" \
    "jmp hook_"#s"\n\t"  \
  \
    ".globl "#s"_code_space\n\t"  \
    #s"_code_space:\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
    ".long 0\n\t"  \
  \
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

#define HIJACK_SIZE 16
#define LONG_JMP_CODE_LEN 9
int fill_nop_for_target(void *, void *);
int fill_nop_for_code_space(void *, void *);
#define init_arch_write_map_page(x) (0)
#define MAX_INSTRUCTIONS 10
#endif