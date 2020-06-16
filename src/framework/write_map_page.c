#include "include/klog.h"
#include "include/common_data.h"
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <asm/memory.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <linux/mm.h>

void *_stext_ptr = NULL, *_etext_ptr = NULL, 
    *_sinittext_ptr = NULL, *_einittext_ptr = NULL;

int init_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)_sinittext_ptr &&
	    addr < (unsigned long)_einittext_ptr)
		return 1;
	return 0;
}

int core_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)_stext_ptr &&
	    addr < (unsigned long)_etext_ptr)
		return 1;

	if (system_state < SYSTEM_RUNNING &&
	    init_kernel_text(addr))
		return 1;
	return 0;
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
        logerror("Try to write word across page boundary %p\n", target);
        return -EFAULT;
    }

    if (operate_on_kernel && !core_kernel_text((unsigned long)target)) {
        logerror("Try to write to non kernel address %p\n", target);
        return -EFAULT;
    }

    if (operate_on_kernel) {
        page = phys_to_page(__pa(target));
    } else {
        page = vmalloc_to_page(target);
    }

    if (!page) {
        logerror("Cannot get page of address %p\n", target);
        return -EFAULT;
    }

    new_target = vm_map_ram(&page, 1, -1, PAGE_KERNEL_EXEC);
    if (!new_target) {
        logerror("Remap address %p failed\n", target);
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
    long ret = 0;
 
    if (!!(ret = probe_kernel_write(target, source, size))) {
        ret = remap_write_range(target, source, size, operate_on_kernel);
    }
    return (int)ret; 
}

int init_write_map_page(void)
{
    _stext_ptr = (void *)find_func("_stext");
    _etext_ptr = (void *)find_func("_etext");
    _sinittext_ptr = (void *)find_func("_sinittext");
    _einittext_ptr = (void *)find_func("_einittext");
    
    if (_stext_ptr && _etext_ptr && _sinittext_ptr && _einittext_ptr) {
        return 0;
    }
    return -1;
}