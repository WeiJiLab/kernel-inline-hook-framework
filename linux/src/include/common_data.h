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
	void *target;			// The target function to be hooked.
	void *hook_dest;		// Target been hijacked to, aka the hook
					// template addr.
	void *template_return_addr;	// The starting addr of untouched
					// instructions of target function.
	void *hook_template_code_space; // The new addr for original target
					// function to resume.
	void *hook_func;		// The real hook function for target
	char *mod_name;			// hook_func belongs to which module
	bool enabled;
	struct hlist_node node;
	unsigned char target_code[HIJACK_SIZE];
};

/**
 * arg1: the original function address which you'd like to hijack.
 * arg2: GET_TEMPLATE_ADDERSS() is the trampoline template address
 *       that your original function will be hijacked to firstly.
 *       Then the trampoline will jump to your hook function.
 * arg3: GET_CODESPACE_ADDERSS() is the new address of your original
 *       function, if you'd like to call it later. If you will never
 *       call the original function, simply leave it to be NULL.
 * arg4: GET_HOOK_FUNC_ADDRESS() is your hook function address, which
 *       is used for stack safety check when disabling the hook.
 * arg5: This module's name.
 */
int hijack_target_prepare(void *target, void *hook_dest,
	void *hook_template_code_space, void *hook_func, char *mod_name);
int hijack_target_enable(void *target);
int hijack_target_disable(void *target, bool need_remove);
void hijack_target_disable_all(bool need_remove, char *mod_name);
void *find_func(const char *name);

#define HIJACK_TARGET_PREP_HOOK(addr, fn) \
	hijack_target_prepare(addr, GET_TEMPLATE_ADDERSS(fn), \
		GET_CODESPACE_ADDERSS(fn), GET_HOOK_FUNC_ADDRESS(fn), \
		module_name(THIS_MODULE))

#define HIJACK_TARGET_PREP_REPL(addr, fn) \
	hijack_target_prepare(addr, GET_TEMPLATE_ADDERSS(fn), \
		NULL, GET_HOOK_FUNC_ADDRESS(fn), \
		module_name(THIS_MODULE))

#define SHOW_KSYM_CACHE 1
#define CLEAN_ALL_KSYM_CACHE (1 << 1)
#endif