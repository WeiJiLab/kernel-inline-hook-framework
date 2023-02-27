#include "hijack_arm.h"
#include <asm/cacheflush.h>

//There MUST be 4
/*
    ldr pc, [pc, #-0x4]
    .addr
*/
const char long_jmp_code[4]="\x04\xf0\x1f\xe5";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
    memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
    memcpy(fill_dest + sizeof(long_jmp_code), &hijack_to_func, sizeof(void *));
}

/*
* Refer to http://engold.ui.ac.ir/~nikmehr/Appendix_B2.pdf
*/
bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;

    //todo: we want to fix these instructions
	switch (instruction & 0xfe000000u) {
		case 0xfa000000u:  // blx
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f000000u) {
		case 0x0a000000u:  // b
		case 0x0b000000u:  // bl
		ret = false;
		goto out;
	}

	switch (instruction & 0xff000ffu) {
		case 0x0120001fu:  // bx
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f00f010u) {
		case 0x0000f000u:  // and eor sub rsb add adc sbs rsc to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f00f090u) {
		case 0x0000f010u:  // and eor sub rsb add adc sbs rsc to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0fe0f000u) {
		case 0x01a0f000u:  // mov to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0e5ff000u) {
		case 0x041ff000u:  // ldr to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0ffff000u) {
		case 0x028ff000u:  // adr to PC
		case 0x024ff000u:
		ret = false;
		goto out;
	}

out:
    if (!ret) {
        printk(KERN_ALERT"instruction %x cannot be hijacked!\n", instruction);
    }
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

void (*__patch_text_real_ptr)(void *, unsigned int, bool) = NULL;
void *find_func(const char *name);

int hook_write_range(void *target, void *source, int size)
{
    int i;
    for (i = 0; i < size; i = i + INSTRUCTION_SIZE) {
        __patch_text_real_ptr(target + i, *(unsigned int *)(source + i), true);
    }

    return 0;
}

int init_arch_write_map_page(void)
{
    __patch_text_real_ptr = (void *)find_func("__patch_text_real");
    return !__patch_text_real_ptr;
}