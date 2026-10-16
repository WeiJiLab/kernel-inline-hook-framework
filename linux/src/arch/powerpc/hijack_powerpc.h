#ifndef _HOOK_POWERPC_H_
#define _HOOK_POWERPC_H_

#include <asm/asm-offsets.h>
#include <linux/stringify.h>

#define HOOK_FUNC_TEMPLATE(s)			\
extern void hook_##s##_template(void);		\
asm (						\
	".section \".rodata\"			\n\t" \
	#s"_name:				\n\t" \
        ".asciz  \""#s"\"			\n\t" \
						\
	".section \".data\"			\n\t" \
	".balign 8				\n\t" \
	#s"_r2:					\n\t" \
	".zero 512				\n\t" \
	#s"_lr:					\n\t" \
	".zero 512				\n\t" \
						\
	".section \".text\"			\n\t" \
	".quad .TOC.-hook_"#s"_template		\n\t" \
	".globl hook_"#s"_template		\n\t" \
	"hook_"#s"_template:			\n\t" \
	"mr	0, 2				\n\t" \
	"ld	2, -8(12)			\n\t" \
	"add	2, 2, 12			\n\t" \
						\
	"lhz	11, "__stringify(PACAPACAINDEX)"(13)\n\t" \
	"sldi	11, 11, 3			\n\t" \
						\
	"addis	12, 2, "#s"_r2@toc@ha		\n\t" \
	"addi	12, 12, "#s"_r2@toc@l		\n\t" \
	"add	12, 12, 11			\n\t" \
	"std	0, 0(12)			\n\t" \
						\
	"mflr	0				\n\t" \
	"addis	12, 2, "#s"_lr@toc@ha		\n\t" \
	"addi	12, 12, "#s"_lr@toc@l		\n\t" \
	"add	12, 12, 11			\n\t" \
	"std	0, 0(12)			\n\t" \
						\
	"addis	12, 2, hook_"#s"_template@toc@ha\n\t" \
	"addi	12, 12, hook_"#s"_template@toc@l\n\t" \
	"addi	12, 12, 88			\n\t" \
	"mtlr	12				\n\t" \
						\
	"addis	12, 2, hook_"#s"@toc@ha		\n\t" \
	"addi	12, 12, hook_"#s"@toc@l		\n\t" \
	"mtctr	12				\n\t" \
	"bctr					\n\t" \
						\
	"lhz	11, "__stringify(PACAPACAINDEX)"(13)\n\t" \
	"sldi	11, 11, 3			\n\t" \
						\
	"addis	12, 2, "#s"_r2@toc@ha		\n\t" \
	"addi	12, 12, "#s"_r2@toc@l		\n\t" \
	"add	12, 12, 11			\n\t" \
	"ld	0, 0(12)			\n\t" \
	"addis	12, 2, "#s"_lr@toc@ha		\n\t" \
	"addi	12, 12, "#s"_lr@toc@l		\n\t" \
	"add	12, 12, 11			\n\t" \
	"mr	2, 0				\n\t" \
	"ld	0, 0(12)			\n\t" \
	"mtlr	0				\n\t" \
	"blr					\n\t" \
						\
	"mflr	0				\n\t" \
	"stdu	1, -72(1)			\n\t" \
	"std	0, 40(1)			\n\t" \
	"std	3, 48(1)			\n\t" \
	"addis	3, 2, "#s"_name@toc@ha		\n\t" \
	"addi	3, 3, "#s"_name@toc@l		\n\t" \
	"bl	find_func			\n\t" \
	"nop					\n\t" \
	"mr	12, 3				\n\t" \
	"ld	3, 48(1)			\n\t" \
	"ld	0, 40(1)			\n\t" \
	"mtlr	0				\n\t" \
	"addi	1, 1, 72			\n\t" \
						\
	".globl "#s"_code_space\n\t"		\
	#s"_code_space:\n\t"			\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	/********** */				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
	".long	0\n\t"				\
);

#define GET_TEMPLATE_ADDERSS(s)					\
({								\
	void *template;						\
	__asm__ volatile (					\
		"addis %0,2,hook_"#s"_template@toc@ha\n\t"	\
		"addi %0,%0,hook_"#s"_template@toc@l\n\t":	\
		"=r"(template)					\
	);							\
	template;						\
})

#define GET_CODESPACE_ADDERSS(s)				\
({								\
	void *codespace;					\
	__asm__ volatile (					\
		"addis %0,2,"#s"_code_space@toc@ha\n\t"		\
		"addi %0,%0,"#s"_code_space@toc@l\n\t":		\
		"=r"(codespace)					\
	);							\
	codespace;						\
})

/* 13 instructions above xx_code_space */
#define RESUME_FUNC_ADDERSS(s) 					\
(GET_CODESPACE_ADDERSS(s) - 13 * INSTRUCTION_SIZE)

#define GET_HOOK_FUNC_ADDRESS(s)				\
({								\
	void *hook_func;					\
	__asm__ volatile (					\
		"addis %0,2,hook_"#s"@toc@ha\n\t"		\
		"addi %0,%0,hook_"#s"@toc@l\n\t":		\
		"=r"(hook_func)					\
	);							\
	hook_func;						\
})

#define INSTRUCTION_SIZE 4
#define HIJACK_INST_NUM 11
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define fill_nop_for_target(x, y) (0)
#define fill_nop_for_code_space(x, y) (0)

#define LOCAL_FUNC_OFFSET(target) \
({ \
	ppc_function_local(target) - target; \
})

int init_arch(void);
void *ppc_function_local(void *func);
#endif