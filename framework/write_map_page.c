#include "include/klog.h"
#include "include/common_data.h"
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <asm/memory.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>

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

int remap_write_range(void *target, void *source)
{
    struct page *page = NULL;
    void *new_target = NULL;

    if ((((unsigned long)target + HIJACK_SIZE) ^ (unsigned long)target) & (~ 0xfff)) {
        logerror("Try to write word across page boundary %p\n", target);
        return -EFAULT;
    }

    if (!core_kernel_text((unsigned long)target)) {
        logerror("Try to write to non kernel address %p\n", target);
        return -EFAULT;
    }

    if (!(page = phys_to_page(__pa(target)))) {
        logerror("Cannot get page of address %p\n", target);
        return -EFAULT;
    }

    new_target = vm_map_ram(&page, 1, -1, PAGE_KERNEL_EXEC);
    if (!new_target) {
        logerror("Remap address %p failed\n", target);
        return -EFAULT;
    } else {
        memcpy(new_target + ((unsigned long)target & 0xfff), source, HIJACK_SIZE);
        vm_unmap_ram(new_target, 1);
        flush_icache_range((unsigned long)target, (unsigned long)target + HIJACK_SIZE);
        return 0;
    }
}

int hook_write_range(void *target, void *source)
{
    long ret = 0;
 
    if (!!(ret = probe_kernel_write(target, source, HIJACK_SIZE))) {
        ret = remap_write_range(target, source);
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