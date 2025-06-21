#include "hijack_amd64.h"
#include <sys/systm.h>
#include "distorm/distorm.h"
#include "include/common_data.h"

#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>

/*
	push 	%rax
	movabs 	$addr, %rax
	jmp 	*%rax
	pop 	%rax
*/
const char long_jmp_code[14]="\x50\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0\x58";

void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy((char *)fill_dest + 3, &hijack_to_func, sizeof(void *));
}

static _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];

static int disass_target(void *target)
{
	unsigned int decodedInstructionsCount = 0, ret = 0, i;
	_DecodeResult res;

	res = distorm_decode(0, (unsigned char *)target,
			HIJACK_SIZE, Decode64Bits,
			decodedInstructions, MAX_INSTRUCTIONS,
			&decodedInstructionsCount);

	if (res == DECRES_INPUTERR) {
		printf("Disassemble %lx failed!\n", (unsigned long)target);
		return -1;
	}

	for (i = 0; i < decodedInstructionsCount; i++) {
		ret += decodedInstructions[i].size;
		if (ret >= LONG_JMP_CODE_LEN)
			break;
	}
	if (ret >= LONG_JMP_CODE_LEN)
		return ret;
	else
		return -1;
}

/* \x90: nop */
int fill_nop_for_target(void *fill_dest, void *target)
{
	int actual_len = disass_target(target);
	if (actual_len < 0)
		return actual_len;
	memset((char *)fill_dest + LONG_JMP_CODE_LEN, '\x90', actual_len - LONG_JMP_CODE_LEN);
	return 0;
}

int fill_nop_for_code_space(void *fill_dest, void *target)
{
	int actual_len = disass_target(target);
	if (actual_len < 0)
		return actual_len;	
	memset((char *)fill_dest + actual_len, '\x90', HIJACK_SIZE - actual_len);
	return 0;
}

/* skip the check */
bool check_target_can_hijack(void *target)
{
	return true;
}

int hook_write_range(void *target, void *source, int size)
{
	bool old_wp;
	char *dest = (char *)target;
	char *src = (char *)source;
	
	old_wp = disable_wp();
	while (size-- > 0) {
		*dest++ = *src++;
	}
	restore_wp(old_wp);
	return 0;
}