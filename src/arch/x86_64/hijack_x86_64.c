#include "hijack_x86_64.h"
#include "distorm/distorm.h"
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <linux/mm.h>

#define MAX_INSTRUCTIONS 20
_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
/*
	push 	%rax
	movabs 	$addr, %rax
	jmp 	*%rax
	pop 	%rax
*/
const char long_jmp_code[14]="\x50\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0\x58";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy(fill_dest + 3, &hijack_to_func, sizeof(void *));
}

int disass_target(void *target)
{
	unsigned int decodedInstructionsCount = 0, ret = 0, i;
	_DecodeResult res;
	res = distorm_decode(0, (const unsigned char *)target,
			HIJACK_SIZE, Decode64Bits,
			decodedInstructions, MAX_INSTRUCTIONS,
			&decodedInstructionsCount);
	if (res == DECRES_INPUTERR) {
		printk(KERN_ALERT"Disassemble %p failed!\n", target);
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
	memset(fill_dest + LONG_JMP_CODE_LEN, '\x90', actual_len - LONG_JMP_CODE_LEN);
	return 0;
}

int fill_nop_for_code_space(void *fill_dest, void *target)
{
	int actual_len = disass_target(target);
	if (actual_len < 0)
		return actual_len;	
	memset(fill_dest + actual_len, '\x90', HIJACK_SIZE - actual_len);
	return 0;
}

/* skip the check */
bool check_target_can_hijack(void *target)
{
	return true;
}

/*
* Since we are inserting jump instrcutions, if we insert in kernel area(to jump out of kernel),
* we should use phys_to_page(__pa(target)), if we insert in kernel_module(to jump back to kernel), 
* we should use vmalloc_to_page(target) instead
*/
int remap_write_range(void *target, void *source, int size, bool operate_on_kernel)
{
    struct page *page = NULL;
    void *new_target = NULL;

    if ((((unsigned long)target + size) ^ (unsigned long)target) & PAGE_MASK) {
        printk(KERN_ALERT"Try to write word across page boundary %p\n", target);
        return -EFAULT;
    }

    if (operate_on_kernel && !core_kernel_text((unsigned long)target)) {
        printk(KERN_ALERT"Try to write to non kernel address %p\n", target);
        return -EFAULT;
    }

    if (operate_on_kernel) {
	page = virt_to_page(target);
    } else {
        page = vmalloc_to_page(target);
    }

    if (!page) {
        printk(KERN_ALERT"Cannot get page of address %p\n", target);
        return -EFAULT;
    }

    new_target = vm_map_ram(&page, 1, -1);
    if (!new_target) {
        printk(KERN_ALERT"Remap address %p failed\n", target);
        return -EFAULT;
    } else {
        memcpy(new_target + ((unsigned long)target & (~ PAGE_MASK)), source, size);
        vm_unmap_ram(new_target, 1);
        flush_icache_range((unsigned long)target, (unsigned long)target + size);
        return 0;
    }
}

int hook_write_range(void *target, void *source, int size, bool operate_on_kernel)
{
    long ret = remap_write_range(target, source, size, operate_on_kernel);
    return (int)ret; 
}