#include "include/common_data.h"
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/slab.h>

enum mod_license {
	NOT_GPL_ONLY,
	GPL_ONLY,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
struct kernel_symbol {
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
	int value_offset;
	int name_offset;
	int namespace_offset;
#else
	unsigned long value;
	const char *name;
	const char *namespace;
#endif
};
#endif

struct symsearch {
	const struct kernel_symbol *start, *stop;
	const s32 *crcs;
	enum mod_license license;
};

struct find_symbol_arg {
	/* Input */
	const char *name;
	bool gplok;
	bool warn;

	/* Output */
	struct module *owner;
	const s32 *crc;
	const struct kernel_symbol *sym;
	enum mod_license license;
};

/******************************************************************************/

static struct symsearch arr[2];
static struct list_head *modules_ptr = NULL;
static struct mutex *module_mutex_ptr = NULL;
static bool (*find_exported_symbol_in_section_ptr)(const struct symsearch *,
					    struct module *,
					    struct find_symbol_arg *) = NULL;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *) = NULL;

static DEFINE_HASHTABLE(ksyms_cache_hashtable, DEFAULT_HASH_BUCKET_BITS);
static rwlock_t ksyms_cache_hashtable_lock;
extern int hijack_target_prepare(void *, void *, void *);
extern int hijack_target_enable(void *);
static bool resolve_kallsyms_symbol(struct find_symbol_arg *);

/******************************************************************************/

static inline void module_assert_mutex_or_preempt(void)
{
#ifdef CONFIG_LOCKDEP
	if (unlikely(!debug_locks))
		return;

	WARN_ON_ONCE(!rcu_read_lock_sched_held() &&
		     !lockdep_is_held(module_mutex_ptr));
#endif
}

__nocfi bool hook_find_symbol(struct find_symbol_arg *fsa)
{
	struct module *mod;
	unsigned int i;

	module_assert_mutex_or_preempt();

	for (i = 0; i < ARRAY_SIZE(arr); i++)
		if (find_exported_symbol_in_section_ptr(&arr[i], NULL, fsa))
			return true;

	list_for_each_entry_rcu(mod, modules_ptr, list,
				lockdep_is_held(module_mutex_ptr)) {
		struct symsearch arr[] = {
			{ mod->syms, mod->syms + mod->num_syms, mod->crcs,
			  NOT_GPL_ONLY },
			{ mod->gpl_syms, mod->gpl_syms + mod->num_gpl_syms,
			  mod->gpl_crcs,
			  GPL_ONLY },
		};

		if (mod->state == MODULE_STATE_UNFORMED)
			continue;

		for (i = 0; i < ARRAY_SIZE(arr); i++)
			if (find_exported_symbol_in_section_ptr(&arr[i], mod, fsa))
				return true;
	}

	if (resolve_kallsyms_symbol(fsa))
		return true;

	pr_debug("Failed to find symbol %s\n", fsa->name);
	return false;
}
HOOK_FUNC_TEMPLATE(find_symbol);

/******************************************************************************/

static void operate_ksyms_cache(uint32_t status)
{
	int bkt;
	struct hlist_node *tmp;
	struct ksym_cache *ca;

	if (status & SHOW_KSYM_CACHE) {
		read_lock(&ksyms_cache_hashtable_lock);
		hash_for_each_safe(ksyms_cache_hashtable, bkt, tmp, ca, node) {
			printk(KERN_ALERT"ksyms_cache: %s, %lx\n", ca->ksym_name, ca->ksym_addr);
		}
		read_unlock(&ksyms_cache_hashtable_lock);
	}
	
	if (status & CLEAN_ALL_KSYM_CACHE) {
		write_lock(&ksyms_cache_hashtable_lock);
		hash_for_each_safe(ksyms_cache_hashtable, bkt, tmp, ca, node) {
			hash_del(&ca->node);
			kfree(ca);
		}
		write_unlock(&ksyms_cache_hashtable_lock);
	}
}

static __nocfi bool resolve_kallsyms_symbol(struct find_symbol_arg *fsa)
{
	struct kernel_symbol *sym = NULL;
	void *sym_addr = NULL;
	struct ksym_cache *ca = NULL;
	uint32_t name_hash = jhash_string(fsa->name);

	//first, we lookup the cached hashtable
	read_lock(&ksyms_cache_hashtable_lock);
	hash_for_each_possible(ksyms_cache_hashtable, ca, node, name_hash) {
		if (!strncmp(fsa->name, ca->ksym_name, sizeof(ca->ksym_name))) {
			sym = (struct kernel_symbol *)ca;
			read_unlock(&ksyms_cache_hashtable_lock);
			goto success;
		}
	}
	read_unlock(&ksyms_cache_hashtable_lock);

	//second, we lookup the kallsyms
	sym_addr = (void *)kallsyms_lookup_name_ptr(fsa->name);
	if (!sym_addr)
		return false;

	ca = (struct ksym_cache *)kzalloc(sizeof(struct ksym_cache), GFP_KERNEL);
	if (!ca) {
		printk(KERN_ALERT"No memory cache allocated for %s\n", fsa->name);
		return false;
	}

	ca->ksym_addr = sym_addr;
	strncpy(ca->ksym_name, fsa->name, sizeof(ca->ksym_name));
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS    
	ca->value_offset = (int)((unsigned long)sym_addr - (unsigned long)&ca->value_offset);
	ca->name_offset = (int)((unsigned long)ca->ksym_name - (unsigned long)&ca->name_offset);
	ca->namespace_offset = 0;
#else
	ca->value = (unsigned long)sym_addr;
	ca->name = ca->ksym_name;
	ca->namespace = NULL;
#endif

	//third, we insert the new cache into hashtable
	write_lock(&ksyms_cache_hashtable_lock);
	hash_add(ksyms_cache_hashtable, &ca->node, name_hash);
	write_unlock(&ksyms_cache_hashtable_lock);
	sym = (struct kernel_symbol *)ca;

	operate_ksyms_cache(SHOW_KSYM_CACHE);

success:
	fsa->owner = NULL;
	fsa->crc = NULL;
	fsa->sym = sym;
	fsa->license = 0;
	return true;
}

void remove_symbol_resolver_cache(void)
{
	operate_ksyms_cache(CLEAN_ALL_KSYM_CACHE);
}

__nocfi void *find_func(const char *name)
{
	void *ret = NULL;
	ret = (void *)kallsyms_lookup_name_ptr(name);
	if (!ret) {
		printk(KERN_ALERT"Symbol %s not found!\n", name);
	}
	return ret;
}
EXPORT_SYMBOL(find_func);

int init_kallsyms_lookup_func(void)
{
	int ret;

	// First, we get kallsyms_lookup_name()
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_ALERT"register_kprobe failed!\n");
		goto out;
	}
	kallsyms_lookup_name_ptr = (void *)(kp.addr) - HOOK_TARGET_OFFSET;
	unregister_kprobe(&kp);
	ret = 0;
out:
	return ret;
}

int init_simplify_symbols_hook(void)
{
	void *find_symbol_ptr;

	struct symsearch *__start___ksymtab_ptr = find_func("__start___ksymtab");
	struct symsearch *__stop___ksymtab_ptr = find_func("__stop___ksymtab");
	struct symsearch *__start___kcrctab_ptr = find_func("__start___kcrctab");
	struct symsearch *__start___ksymtab_gpl_ptr = find_func("__start___ksymtab_gpl");
	struct symsearch *__stop___ksymtab_gpl_ptr =  find_func("__stop___ksymtab_gpl");
	struct symsearch *__start___kcrctab_gpl_ptr = find_func("__start___kcrctab_gpl");
	
	rwlock_init(&ksyms_cache_hashtable_lock);
	modules_ptr = find_func("modules");
	module_mutex_ptr = find_func("module_mutex");
	find_exported_symbol_in_section_ptr = find_func("find_exported_symbol_in_section");

	if (!__start___ksymtab_ptr || !__stop___ksymtab_ptr ||
	    !__start___kcrctab_ptr || !__start___ksymtab_gpl_ptr ||
	    !__stop___ksymtab_gpl_ptr || !__start___kcrctab_gpl_ptr ||
	    !modules_ptr || !module_mutex_ptr ||
	    !find_exported_symbol_in_section_ptr)
		goto out;

	arr[0] = (struct symsearch){ (struct kernel_symbol *)__start___ksymtab_ptr,
				     (struct kernel_symbol *)__stop___ksymtab_ptr,
		   		     (s32 *)__start___kcrctab_ptr, NOT_GPL_ONLY };
	arr[1] = (struct symsearch){ (struct kernel_symbol *)__start___ksymtab_gpl_ptr,
				     (struct kernel_symbol *)__stop___ksymtab_gpl_ptr,
		   		     (s32 *)__start___kcrctab_gpl_ptr, GPL_ONLY };

	find_symbol_ptr = find_func("find_symbol");

	if (!find_symbol_ptr)
		goto out;
	
	if (hijack_target_prepare(find_symbol_ptr,
				  GET_TEMPLATE_ADDERSS(find_symbol),
				  NULL)) {
		printk(KERN_ALERT"find_symbol prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(find_symbol_ptr)) {
		printk(KERN_ALERT"find_symbol enable error!\n");
		goto out;
	}

	return 0;
out:
	return -EFAULT;
}
