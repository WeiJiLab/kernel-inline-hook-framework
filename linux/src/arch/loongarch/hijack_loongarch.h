#ifndef _HOOK_LOONGARCH_H_
#define _HOOK_LOONGARCH_H_

#define HOOK_FUNC_TEMPLATE(s)			\
extern void hook_##s##_template(void);		\
asm (						\
	".globl hook_"#s"_template\n\t"		\
	"hook_"#s"_template:\n\t"		\
	"ld.d	$t1, $sp, 8\n\t"		\
	"addi.d $sp, $sp, 16\n\t"		\
	"b hook_"#s"\n\t"			\
						\
	".globl "#s"_code_space\n\t"		\
	#s"_code_space:\n\t"			\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
						\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
	".word 0\n\t"				\
);

#define GET_TEMPLATE_ADDERSS(s) \
({  \
	void *template; \
	__asm__ volatile ("la.pcrel %0, hook_"#s"_template\n\t":"=r"(template)); \
	template;  \
})

#define GET_CODESPACE_ADDERSS(s) \
({  \
	void *codespace; \
	__asm__ volatile ("la.pcrel %0, "#s"_code_space\n\t":"=r"(codespace)); \
	codespace;  \
})

#define RESUME_FUNC_ADDERSS(s) GET_CODESPACE_ADDERSS(s)

#define GET_HOOK_FUNC_ADDRESS(s) \
({  \
	void *hook_func; \
	__asm__ volatile ("la.pcrel %0, hook_"#s"\n\t":"=r"(hook_func)); \
	hook_func;  \
})

#define INSTRUCTION_SIZE 4
#define HIJACK_INST_NUM 9
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define fill_nop_for_target(x, y) (0)
#define fill_nop_for_code_space(x, y) (0)
#define LOCAL_FUNC_OFFSET(x) (0)
int init_arch(void);
#endif