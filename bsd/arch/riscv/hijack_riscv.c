#include "hijack_riscv.h"
#include <machine/cpu.h>
#include <machine/machdep.h>
#include <sys/systm.h>
#include "include/common_data.h"

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

void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy((char *)fill_dest + 14, &hijack_to_func, sizeof(void *));
}

static int disass_target(void *target);
static int disass_target(void *target)
{
	uint16_t insn_prob;
	int off = 0;

	while (off < LONG_JMP_CODE_LEN) {
		insn_prob = *(uint16_t *)((char *)target + off);
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
		printf("BUG! odd instruction length\n");
		return -1;
	}
	for (c = 0; c < actual_len - LONG_JMP_CODE_LEN; c += 2) {
		*(uint16_t *)((char *)fill_dest +
			LONG_JMP_CODE_LEN + c) = 0x0001;
	}
	return 0;
}

int fill_nop_for_code_space(void *fill_dest, void *target)
{
	int c;
	int actual_len = disass_target(target);

	if ((HIJACK_SIZE - actual_len) % 2) {
		printf("BUG! odd instruction length\n");
		return -1;
	}
	for (c = 0; c < HIJACK_SIZE - actual_len; c += 2) {
		*(uint16_t *)((char *)fill_dest +
			actual_len + c) = 0x0001;
	}
	return 0;
}

bool check_target_can_hijack(void *target);
bool check_target_can_hijack(void *target)
{
	uint16_t insn_prob_2;
	uint32_t insn_prob_4;
	int off = 0;
	int inst_len;

	while (off < LONG_JMP_CODE_LEN) {
		insn_prob_2 = *(uint16_t *)((char *)target + off);
		inst_len = ((insn_prob_2 & 0x3) == 0x3 ? 4 : 2);
		switch (inst_len) {
			case 2:
				// Reserve for check insn_prob_2 is hijackable.
				break;
			case 4:
				insn_prob_4 = *(uint32_t *)((char *)target + off);
				if ((insn_prob_4 & 0x7f) == 0x17) // auipc
					return false;
				break;
		}
		off += inst_len;
	}
	return true;
}

int hook_write_range(void *target, void *source, int size);
int hook_write_range(void *target, void *source, int size)
{
	char *dst, *data;

	dst = (char *)target;
	data = (char *)source;
	while (size-- > 0)
		*dst++ = *data++;
	fence_i();

	return 0;
}
