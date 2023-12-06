#include "include/common_data.h"

void *_stext_ptr = NULL, *_etext_ptr = NULL, 
    *_sinittext_ptr = NULL, *_einittext_ptr = NULL;

int (*core_kernel_text_ptr)(unsigned long) = NULL;
bool (*is_module_text_address_ptr)(unsigned long) = NULL;

int init_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)_sinittext_ptr &&
	    addr < (unsigned long)_einittext_ptr)
		return 1;
	return 0;
}

int init_write_map_page(void)
{
    int ret = -1;

    _stext_ptr = (void *)find_func("_stext");
    _etext_ptr = (void *)find_func("_etext");
    _sinittext_ptr = (void *)find_func("_sinittext");
    _einittext_ptr = (void *)find_func("_einittext");
    core_kernel_text_ptr = (void *)find_func("core_kernel_text");
    is_module_text_address_ptr = (void *)find_func("is_module_text_address");

    if (!(_stext_ptr && _etext_ptr && _sinittext_ptr && _einittext_ptr &&
    	  core_kernel_text_ptr && is_module_text_address_ptr)) {
        goto out;
    }
    if (init_arch())
	goto out;
    ret = 0;
out:
    return ret;
}