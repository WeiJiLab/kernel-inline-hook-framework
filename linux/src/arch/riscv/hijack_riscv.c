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
	for (c = 0; c < actual_len - LONG_JMP_CODE_LEN; c += 2) {
		*(u16 *)(fill_dest + LONG_JMP_CODE_LEN + c) = 0x0001;
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
	for (c = 0; c < HIJACK_SIZE - actual_len; c += 2) {
		*(u16 *)(fill_dest + actual_len + c) = 0x0001;
	}
	return 0;
}

/*
 * Fix me:
 * Linux contains ftrace padding at the start of target, which might be
 * over-written by auipc inst later, making the target unhijackable:

   objdump vmlinux:
	ffffffff80457c98 <vfs_read>:
	ffffffff80457c98: 0001  nop
	ffffffff80457c9a: 0001  nop
	ffffffff80457c9c: 0001  nop
	ffffffff80457c9e: 0001  nop

	ffffffff80457ca0 <.LVL1079>:
	ffffffff80457ca0: 7171  addi    sp, sp, -0xb0
	ffffffff80457ca2: f122  sd      s0, 0xa0(sp)
	ffffffff80457ca4: ed26  sd      s1, 0x98(sp)
	ffffffff80457ca6: f506  sd      ra, 0xa8(sp)
	ffffffff80457ca8: 1900  addi    s0, sp, 0xb0

   hexdump memory:
	ffbda297 → auipc   t0, 0xffbda
	00000013 → nop
	7171 → c.addi16sp sp, -176
	f122 → c.sdsp  s0, 160(sp)
	ed26 → c.sdsp  s1, 152(sp)

 * Messing up this auipc doesn't really matters for the inline hook framework,
 * so comment out the following function to let it pass at your own risk.
 */
bool check_target_can_hijack(void *target)
{
	u16 insn_prob_2;
	u32 insn_prob_4;
	int off = 0;
	int inst_len;

	while (off < LONG_JMP_CODE_LEN) {
		insn_prob_2 = *(u16 *)(target + off);
		inst_len = ((insn_prob_2 & 0x3) == 0x3 ? 4 : 2);
		switch (inst_len) {
			case 2:
				// Reserve for check insn_prob_2 is hijackable.
				break;
			case 4:
				insn_prob_4 = *(u32 *)(target + off);
				if ((insn_prob_4 & 0x7f) == 0x17) // auipc
					return false;
				break;
		}
		off += inst_len;
	}
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