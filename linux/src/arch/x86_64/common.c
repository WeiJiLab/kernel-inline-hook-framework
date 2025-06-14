#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <asm/insn.h>
#include "include/common_data.h"

int (*insn_decode_ptr)(struct insn *, const void *, int, enum insn_mode) = NULL;

extern int (*core_kernel_text_ptr)(unsigned long);
extern bool (*is_module_text_address_ptr)(unsigned long);

__nocfi int disass_target(void *target)
{
	struct insn insn;
	int off = 0, ret;

	while (off < LONG_JMP_CODE_LEN) {
		ret = insn_decode_ptr(&insn, target + off, MAX_INSN_SIZE, INSN_MODE_KERN);
		if (ret)
			return ret;
		off += insn.length;
	}
	return off;
}

/* \x90: nop */
int fill_nop_for_target(void *fill_dest, void *target)
{
	int actual_len = disass_target(target);
	if (actual_len < 0)
		return actual_len;
	if (actual_len > HIJACK_SIZE) {
		printk(KERN_ALERT"Maybe long(>=%d) instructions encountered before %llx\n",
			HIJACK_SIZE - LONG_JMP_CODE_LEN, (u64)(target + actual_len));
		return -1;
	}
	memset(fill_dest + LONG_JMP_CODE_LEN, '\x90', actual_len - LONG_JMP_CODE_LEN);
	return 0;
}

int fill_nop_for_code_space(void *fill_dest, void *target)
{
	int actual_len = disass_target(target);
	if (actual_len < 0)
		return actual_len;
	if (actual_len > HIJACK_SIZE) {
		printk(KERN_ALERT"Maybe long(>=%d) instructions encountered before %llx\n",
			HIJACK_SIZE - LONG_JMP_CODE_LEN, (u64)(target + actual_len));
		return -1;
	}
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
__nocfi int remap_write_range(void *target, void *source, int size)
{
	struct page *page = NULL;
	void *new_target = NULL;

	if ((((unsigned long)target + size) ^ (unsigned long)target) & PAGE_MASK) {
		printk(KERN_ALERT"Try to write word across page boundary %lx\n", target);
		return -EFAULT;
	}

	if (core_kernel_text_ptr((unsigned long)target)) {
		page = virt_to_page(target);
	} else if (is_module_text_address_ptr((unsigned long)target)) {
		page = vmalloc_to_page(target);
	} else {
		printk(KERN_ALERT"Try to write to non kernel text address %lx\n", target);
		return -EFAULT;	    
	}

	if (!page) {
		printk(KERN_ALERT"Cannot get page of address %lx\n", target);
		return -EFAULT;
	}

	new_target = vm_map_ram(&page, 1, -1);
	if (!new_target) {
		printk(KERN_ALERT"Remap address %lx failed\n", target);
		return -EFAULT;
	} else {
		memcpy(new_target + ((unsigned long)target & (~ PAGE_MASK)), source, size);
		vm_unmap_ram(new_target, 1);
		flush_icache_range((unsigned long)target, (unsigned long)target + size);
		return 0;
	}
}

int hook_write_range(void *target, void *source, int size)
{
	long ret = remap_write_range(target, source, size);
	return (int)ret; 
}

int init_arch(void) {
	insn_decode_ptr = (void *)find_func("insn_decode");
	return !insn_decode_ptr;
}