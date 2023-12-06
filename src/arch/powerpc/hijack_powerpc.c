#include "hijack_powerpc.h"
#include <asm/cacheflush.h>
#include <asm/inst.h>

/*
  Usually the first 3 instructions are doing: 1) save r2, 2) save return addr to
  r0. So we need to save them as kernel env.

	orig_inst 0  \
	orig_inst 1   | => HOOK_TARGET_OFFSET = inst_size * 3
	orig_inst 2  /

	bcl 	20, 31, .+4
	mflr	12
	ld	12, 16(12)
	mtctr	12
	bctr	12
	.addr(low)
	.addr(high)
*/

const char long_jmp_code[28]=
	"\x05\x00\x9f\x42\xa6\x02\x88\x7d\x10\x00\x8c\xe9\xa6\x03\x89\x7d\x20\x04\x80\x4e\x00\x00\x00\x00\x00\x00\x00\x00";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy(fill_dest + 5 * INSTRUCTION_SIZE, &hijack_to_func, sizeof(void *));
}

bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;
	return ret;
}

bool check_target_can_hijack(void *target)
{
	int offset = 0;
	for (; offset < HOOK_TARGET_OFFSET + HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
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
	ppc_inst_t inst;

	for (i = 0; i < size; i = i + INSTRUCTION_SIZE) {
		*(u32 *)&inst = *(u32 *)(source + i);
		ret = patch_instruction_ptr(target + i, inst);
		if (ret) {
			goto out;
		}
	}

out:
    return ret; 
}

int init_arch(void)
{
	patch_instruction_ptr = (void *)find_func("patch_instruction");
	return !patch_instruction_ptr;
}