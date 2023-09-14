#ifndef _COMMON_DATA_H_
#define _COMMON_DATA_H_

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/types.h>
#include <linux/kallsyms.h>

#ifdef _ARCH_ARM64_
#include "hijack_arm64.h"
#include <asm/memory.h>
#endif

#ifdef _ARCH_ARM_
#include "hijack_arm.h"
#include <asm/memory.h>
#endif

#ifdef _ARCH_X86_64_
#include "hijack_x86_64.h"
#include <asm/page.h>
#endif

#ifdef _ARCH_X86_
#include "hijack_x86.h"
#include <asm/page.h>
#endif

#ifdef _ARCH_POWERPC_
#include "hijack_powerpc.h"
#include <asm/page.h>
#endif

#define DEFAULT_HASH_BUCKET_BITS   17

#define jhash_pointer(pointer)       jhash((&pointer), sizeof(pointer), 0x95279527)
#define jhash_string(str)            jhash((str), strlen(str), 0x12345678)

struct ksym_cache {
//Warning!!! don't put any thing here, we want to hack kernel_symbol, so that
//struct kernel_symbol *sym_addr = (struct kernel_symbol *)ksym_cache_addr;
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS    
	int value_offset;
	int name_offset;
	int namespace_offset;
#else
	unsigned long value;
	const char *name;
	const char *namespace;
#endif
	struct hlist_node node;
	void *ksym_addr;
	char ksym_name[KSYM_NAME_LEN];
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

void *find_func(const char *name);

#define SHOW_KSYM_CACHE 1
#define CLEAN_ALL_KSYM_CACHE (1 << 1)
#endif