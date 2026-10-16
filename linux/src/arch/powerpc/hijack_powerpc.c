#include "hijack_powerpc.h"
#include <asm/cacheflush.h>
#include <asm/inst.h>
#include <asm/text-patching.h>

/*
	mflr    r0
	bcl 	20, 31, .+4
	mflr	12
	ld	12, 20(12)
	mtctr	12
	mtlr	r0
	bctr
	.addr(low)
	.addr(high)
*/

const char long_jmp_code[36]=
	"\xa6\x02\x08\x7c\x05\x00\x9f\x42\xa6\x02\x88\x7d\x14\x00\x8c\xe9\xa6\x03\x89\x7d\xa6\x03\x08\x7c\x20\x04\x80\x4e\x00\x00\x00\x00\x00\x00\x00\x00";

const char nop_code[4]="\x00\x00\x00\x60";

/* Only support CONFIG_PPC64_ELF_ABI_V2 */
void *ppc_function_local(void *func)
{
	void *ret;
	u32 *insn = func;

	if ((((*insn & OP_RT_RA_MASK) == ADDIS_R2_R12) ||
	     ((*insn & OP_RT_RA_MASK) == LIS_R2)) &&
	    ((*(insn+1) & OP_RT_RA_MASK) == ADDI_R2_R2)) {
		ret = (void *)(insn + 2);
	} else {
		ret = func;
	}

	return ret;
}

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	if (ppc_function_local(fill_dest) != fill_dest) {
		memcpy(fill_dest + 2 * INSTRUCTION_SIZE, long_jmp_code, sizeof(long_jmp_code));
		memcpy(fill_dest + (2 + 7) * INSTRUCTION_SIZE, &hijack_to_func, sizeof(void *));
	} else {
		memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
		memcpy(fill_dest + 7 * INSTRUCTION_SIZE, &hijack_to_func, sizeof(void *));
		for (int i = 0; i < 2; i++)
			memcpy(fill_dest + sizeof(long_jmp_code) + i * INSTRUCTION_SIZE,
				nop_code, INSTRUCTION_SIZE);
	}
}

bool (*is_conditional_branch_ptr)(ppc_inst_t) = NULL;

bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;

	if (is_conditional_branch_ptr(ppc_inst(instruction)))
		ret = false;

	return ret;
}

bool check_target_can_hijack(void *target)
{
	int offset = 0;
	for (; offset < HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
		if (!check_instruction_can_hijack(*(uint32_t *)(target + offset)))
			return false;
	}
	return true;
}

int (*patch_instruction_ptr)(u32 *, ppc_inst_t) = NULL;
void *find_func(const char *name);

int hook_write_range(void *target, void *source, int size)
{
	int ret = 0, i;
	ppc_inst_t inst = {0};

	for (i = 0; i < size; i = i + INSTRUCTION_SIZE) {
		inst.val = *(u32 *)(source + i);
		ret = patch_instruction_ptr(target + i, inst);
		if (ret) {
			goto out;
		}
	}

out:
    return ret; 
}

extern unsigned long (*kallsyms_lookup_name_ptr)(const char *);
void *find_func(const char *name)
{
	void *ret = NULL;

	if (kallsyms_lookup_name_ptr == ppc_function_local(kallsyms_lookup_name_ptr))
		kallsyms_lookup_name_ptr -= 2 * sizeof(u32);
	ret = (void *)kallsyms_lookup_name_ptr(name);
	if (!ret) {
		printk(KERN_ALERT"Func %s not found!\n", name);
		goto out;
	}

	ret = ppc_function_local(ret);
	ret -= 2 * sizeof(u32);
out:
	return ret;
}

int init_arch(void)
{
	patch_instruction_ptr = (void *)find_func("patch_instruction");
	is_conditional_branch_ptr = (void *)find_func("is_conditional_branch");
	if (patch_instruction_ptr && is_conditional_branch_ptr)
		return 0;
	else
		return 1;
}