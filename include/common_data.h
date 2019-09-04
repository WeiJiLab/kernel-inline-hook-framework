#ifndef _COMMON_DATA_H_
#define _COMMON_DATA_H_

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kallsyms.h>
#include "include/klog.h"

#ifdef _ARCH_ARM64_
#include "hijack_arm64.h"
#endif

#ifdef _ARCH_ARM_
#include "hijack_arm.h"
#endif

#define DEFAULT_HASH_BUCKET_BITS   17
#define MAX_KSYM_NAME_LEN 64

#define jhash_pointer(pointer)       jhash((&pointer), sizeof(pointer), 0x95279527)
#define jhash_string(str)            jhash((str), strlen(str), 0x12345678)

struct ksym_cache {
//Warning!!! don't put any thing here, we want to hack kernel_symbol, so that
//struct kernel_symbol *sym_addr = (struct kernel_symbol *)ksym_cache_addr;
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS    
    int value_offset;
	int name_offset;
#else
	unsigned long value;
	char *name;
#endif
    struct hlist_node node;
    void *ksym_addr;
    char ksym_name[MAX_KSYM_NAME_LEN];
};

struct sym_hook {
    void *target;
    void *hook_dest;
    void *template_return_addr;
    void *hook_template_code_space;
    bool enabled;
    struct hlist_node node;
    unsigned char target_code[HIJACK_SIZE];
};

static inline void *find_func(const char *name)
{
	void *ret = NULL;
	ret = (void *)kallsyms_lookup_name(name);
	if (!ret) {
		logerror("Symbol %s not found!", name);
	}
	return ret;
}

#define SHOW_KSYM_CACHE 1
#define CLEAN_ALL_KSYM_CACHE (1 << 1)
#endif