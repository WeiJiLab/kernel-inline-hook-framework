#include <machine/cpu.h>
#include <machine/machdep.h>
#include <sys/systm.h>
#include "hijack_arm64.h"
#include "include/common_data.h"

/*
	stp x1, x0, [sp, #-0x20]!
	ldr x0, 8
	ret x0
	.addr(low)
	.addr(high)
	ldp x1, x0, [sp], #0x20
*/
const char long_jmp_code[24]="\xe1\x03\xbe\xa9\x40\x00\x00\x58\x00\x00\x5f\xd6\x00\x00\x00\x00\x00\x00\x00\x00\xe1\x03\xc2\xa8";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy((char *)fill_dest + 3 * INSTRUCTION_SIZE, &hijack_to_func, sizeof(void *));
}

/*
* Refer to https://github.com/CAS-Atlantic/AArch64-Encoding
*/

static bool check_instruction_can_hijack(uint32_t instruction);
static bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;

	//todo: we want to fix these instructions
	switch(instruction & 0x9f000000u) {
	case 0x10000000u:  //adr  
	case 0x90000000u:  //adrp
		ret = false;
		goto out;
	}
	switch(instruction & 0xfc000000u) {
	case 0x14000000u:  //b  
	case 0x94000000u:  //bl
		ret = false;
		goto out;
	}
	switch(instruction & 0xff000000u) {
	case 0x54000000u:  //b.c  
		ret = false;
		goto out;
	}    
	switch(instruction & 0x7e000000u) {
	case 0x34000000u:  //cbz cbnz
	case 0x36000000u:  //tbz tbnz
		ret = false;
		goto out;
	}
	switch(instruction & 0xbf000000u) {
	case 0x18000000u:  //ldr
		ret = false;
		goto out;
	}
	switch(instruction & 0x3f000000u) {
	case 0x1c000000u:  //ldrv
		ret = false;
		goto out;
	}
	switch(instruction & 0xff000000u) {
	case 0x98000000u:  //ldrsw
		ret = false;
		goto out;
	}

out:
	if (!ret) {
		printf("instruction %x cannot be hijacked!\n", instruction);
	}
	return ret;
}

bool check_target_can_hijack(void *target)
{
	int offset = 0;
	for (; offset < HOOK_TARGET_OFFSET + HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
		if (!check_instruction_can_hijack(*(uint32_t *)((char *)target + offset)))
			return false;
	}
	return true;
}

int hook_write_range(void *target, void *source, int size)
{
	int i;
	char *dst, *data;
	vm_offset_t addr = (vm_offset_t)target;

	if (!arm64_get_writable_addr(addr, &addr)) {
		return 1;
	} else {
		dst = (char *)addr;
		data = (char *)source;
		for (i = 0; i < size; i++)
			*dst++ = *data++;
		dsb(ish);
		cpu_icache_sync_range(addr, (vm_size_t)size);		
	}
	return 0; 
}