#include "hijack_riscv.h"
#include <asm/cacheflush.h>

/*
	addi  sp, sp, -16
	sd    t1, 8(sp)
	auipc t1, 0
	ld    t1, 10(t1)
	jr    t1
	.word low
	.word high
	ld    t1, 8(sp)
	addi  sp, sp, 16
*/

const char long_jmp_code[26]="\x41\x11\x1a\xe4\x17\x03\x00\x00\x03\x33\xa3\x00\x02\x83\x00\x00\x00\x00\x00\x00\x00\x00\x22\x63\x41\x01";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy(fill_dest + 14, &hijack_to_func, sizeof(void *));
}

__nocfi int disass_target(void *target)
{
	u16 insn_prob;
	int off = 0;

	while (off < LONG_JMP_CODE_LEN) {
		insn_prob = *(u16 *)(target + off);
		off += ((insn_prob & 0x3) == 0x3 ? 4 : 2);
	}
	return off;
}

/* \x00\x01: nop */
int fill_nop_for_target(void *fill_dest, void *target)
{
	int c;
	int actual_len = disass_target(target);

	if ((actual_len - LONG_JMP_CODE_LEN) % 2) {
		printk(KERN_ALERT"BUG! odd instruction length\n");
		return -1;
	}
	for (c = actual_len - LONG_JMP_CODE_LEN; c; c = c - 2) {
		memset(fill_dest + LONG_JMP_CODE_LEN + c, '\x00', 1);
		memset(fill_dest + LONG_JMP_CODE_LEN + c - 1, '\x01', 1);
	}
	return 0;
}

int fill_nop_for_code_space(void *fill_dest, void *target)
{
	int c;
	int actual_len = disass_target(target);

	if ((HIJACK_SIZE - actual_len) % 2) {
		printk(KERN_ALERT"BUG! odd instruction length\n");
		return -1;
	}
	for (c = HIJACK_SIZE - actual_len; c; c = c - 2) {
		memset(fill_dest + actual_len + c, '\x00', 1);
		memset(fill_dest + actual_len + c - 1, '\x01', 1);		
	}
	return 0;
}

/* skip the check */
bool check_target_can_hijack(void *target)
{
	return true;
}

void *find_func(const char *name);
int (*patch_text_nosync_ptr)(void *, void *, size_t) = NULL;

int hook_write_range(void *target, void *source, int size)
{
	return patch_text_nosync_ptr(target, source, size);
}

int init_arch(void) {
	patch_text_nosync_ptr = (void *)find_func("patch_text_nosync");
	return !patch_text_nosync_ptr;
}