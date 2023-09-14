#ifndef _HOOK_POWERPC_H_
#define _HOOK_POWERPC_H_

/*
  The following complex jump trampoline will be explained one by one:
  part 1: local data section
  part 2: save kernel env(r2), return addr(r0), hook_"#s"_template addr(r12) to
          stack, then switch to hook_"#s"_template env
  part 3: save the stack r2 to data section _r2
  part 4: save the stack r0 to data section _r0
  part 5: make part 6 to be the return address of real hook_func, then jump to
	  hook_func
  part 6: after return from hook_func, then switch to hook_"#s"_template env,
	  then restore r2, r0 from data section _r2, _r0, then return back to
	  kernel.

  above is enough for replace a kernel function use.
  ------------------------------------------------------------------------------
  below is used for kernel function resume.

  part 7: switch env to hook_##s##_template, and load r2 from data section _r2,
	  that is switch to kernel env.
  part 8: the part of kernel function, been copied here.
  part 9: long jump back to kernel function, to resume the rest of the kernel
	  function.
*/

#define HOOK_FUNC_TEMPLATE(s)			\
extern void hook_##s##_template(void);		\
asm (						\
	".section \".data\"\n\t"		\
	"."#s"_r0:\n\t"				\
	".quad 0\n\t"				\
	"."#s"_r2:\n\t"				\
	".quad 0\n\t"				\
						\
	".section \".text\"\n\t"		\
	".quad .TOC.-hook_"#s"_template\n\t"	\
	".globl hook_"#s"_template\n\t"		\
	"hook_"#s"_template:\n\t"		\
	"stdu	12, -16(1)\n\t"			\
	"stdu	0, -16(1)\n\t"			\
	"stdu	2, -16(1)\n\t"			\
	"ld	2, -8(12)\n\t"			\
	"add	2, 2, 12\n\t"			\
						\
	"addis	12, 2, ."#s"_r2@toc@ha\n\t"	\
	"addi	12, 12, ."#s"_r2@toc@l\n\t"	\
	"ld	0, 0(1)\n\t"			\
	"std	0, 0(12)\n\t"			\
						\
	"addis	12, 2, ."#s"_r0@toc@ha\n\t"	\
	"addi	12, 12, ."#s"_r0@toc@l\n\t"	\
	"ld	0, 16(1)\n\t"			\
	"std	0, 0(12)\n\t"			\
						\
	"ld	12, 32(1)\n\t"			\
	"addi	0, 12, 84\n\t"			\
	"mtlr	0\n\t"				\
	"addi	1, 1, 48\n\t"			\
	"addis	12, 2, hook_"#s"@toc@ha\n\t"	\
	"addi	12, 12, hook_"#s"@toc@l\n\t"	\
	"mtctr	12\n\t"				\
	"bctr\n\t"				\
						\
	"mflr	12\n\t"				\
	"addi	12, 12, -84\n\t"		\
	"ld	2, -8(12)\n\t"			\
	"add	2, 2, 12\n\t"			\
	"addis	12, 2, ."#s"_r0@toc@ha\n\t"	\
	"ld	0, ."#s"_r0@toc@l(12)\n\t"	\
	"mtlr	0\n\t"				\
	"addis	12, 2, ."#s"_r2@toc@ha\n\t"	\
	"ld	2, ."#s"_r2@toc@l(12)\n\t"	\
	"blr\n\t"				\
						\
	".quad	.TOC.-"#s"_code_space\n\t"	\
	".globl	"#s"_code_space\n\t"		\
	#s"_code_space:\n\t"			\
	"ld	2, -8(12)\n\t"			\
	"add	2, 2, 12\n\t"			\
	"addis	12, 2, ."#s"_r2@toc@ha\n\t"	\
	"ld	2, ."#s"_r2@toc@l(12)\n\t"	\
						\
	".long	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
	".long 	0\n\t"				\
						\
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
	codespace;					 	\
})

#define INSTRUCTION_SIZE 4
#define HIJACK_INST_NUM 7
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define fill_nop_for_target(x, y) (0)
#define fill_nop_for_code_space(x, y) (0)
/*
  3 instrucions are saved for saving r2 and r0, we fill long jump start
  from an offset. see hijack_powerpc.c
*/ 
#define HOOK_TARGET_OFFSET (INSTRUCTION_SIZE * 3)
// The real code filling area is 4 instrucions offset of #s"_code_space
#define CODE_SPACE_OFFSET (INSTRUCTION_SIZE * 4)
int init_arch_write_map_page(void);
#endif