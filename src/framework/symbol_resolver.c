#include "include/common_data.h"
#include "include/klog.h"
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <uapi/linux/elf.h>
#include <asm-generic/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/bsearch.h>
#include <linux/string.h>

#ifndef CONFIG_MODVERSIONS
#define symversion(base, idx) NULL
#else
#define symversion(base, idx) ((base != NULL) ? ((base) + (idx)) : NULL)
#endif

static DEFINE_HASHTABLE(ksyms_cache_hashtable, DEFAULT_HASH_BUCKET_BITS);
static rwlock_t ksyms_cache_hashtable_lock;

extern int hijack_target_prepare (void *, void *, void *);
extern int hijack_target_enable(void *);

void operate_ksyms_cache(uint32_t status)
{
	int bkt;
	struct hlist_node *tmp;
	struct ksym_cache *ca;

	if (status & SHOW_KSYM_CACHE) {
		read_lock(&ksyms_cache_hashtable_lock);
		hash_for_each_safe(ksyms_cache_hashtable, bkt, tmp, ca, node) {
			loginfo("ksyms_cache: %s, %p\n", ca->ksym_name, ca->ksym_addr);
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

struct kernel_symbol *resolve_kallsyms_symbol(const char *name)
{
    struct kernel_symbol *sym = NULL;
	void *sym_addr = NULL;
    struct ksym_cache *ca = NULL;
    uint32_t name_hash = jhash_string(name);

	//first, we lookup the cached hashtable
	read_lock(&ksyms_cache_hashtable_lock);
	hash_for_each_possible(ksyms_cache_hashtable, ca, node, name_hash) {
        if (!strncmp(name, ca->ksym_name, sizeof(ca->ksym_name))) {
            sym = (struct kernel_symbol *)ca;
			read_unlock(&ksyms_cache_hashtable_lock);
			goto out;
        }
    }
	read_unlock(&ksyms_cache_hashtable_lock);

	//second, we lookup the kallsyms
    sym_addr = (void *)kallsyms_lookup_name(name);
    if (!sym_addr)
        goto out;
    
    ca = (struct ksym_cache *)kzalloc(sizeof(struct ksym_cache), GFP_ATOMIC);
    if (!ca) {
		loginfo("No memory cache allocated for %s\n", name);
        goto out;
	}

	ca->ksym_addr = sym_addr;
	strncpy(ca->ksym_name, name, sizeof(ca->ksym_name));
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS    
    ca->value_offset = (int)((unsigned long)sym_addr - (unsigned long)&ca->value_offset);
	ca->name_offset = (int)((unsigned long)ca->ksym_name - (unsigned long)&ca->name_offset);
#else
	ca->value = (unsigned long)sym_addr;
	ca->name = ca->ksym_name;
#endif
    
	//third, we insert the new cache into hashtable
	write_lock(&ksyms_cache_hashtable_lock);
	hash_add(ksyms_cache_hashtable, &ca->node, name_hash);
	write_unlock(&ksyms_cache_hashtable_lock);
	sym = (struct kernel_symbol *)ca;

	// operate_ksyms_cache(SHOW_KSYM_CACHE);
out:
	return sym;
}

/*******************************************************************************/

struct find_symbol_arg {
	/* Input */
	const char *name;
	bool gplok;
	bool warn;

	/* Output */
	struct module *owner;
	const unsigned long *crc;
	const struct kernel_symbol *sym;
};

static bool check_symbol(const struct symsearch *syms,
				 struct module *owner,
				 unsigned int symnum, void *data)
{
	struct find_symbol_arg *fsa = data;

	if (!fsa->gplok) {
		if (syms->licence == GPL_ONLY)
			return false;
		if (syms->licence == WILL_BE_GPL_ONLY && fsa->warn) {
			pr_warn("Symbol %s is being used by a non-GPL module, "
				"which will not be allowed in the future\n",
				fsa->name);
		}
	}

#ifdef CONFIG_UNUSED_SYMBOLS
	if (syms->unused && fsa->warn) {
		pr_warn("Symbol %s is marked as UNUSED, however this module is "
			"using it.\n", fsa->name);
		pr_warn("This symbol will go away in the future.\n");
		pr_warn("Please evalute if this is the right api to use and if "
			"it really is, submit a report the linux kernel "
			"mailinglist together with submitting your code for "
			"inclusion.\n");
	}
#endif

	fsa->owner = owner;
	fsa->crc = (unsigned long *)symversion(syms->crcs, symnum);
	fsa->sym = &syms->start[symnum];
	return true;
}

static int cmp_name(const void *va, const void *vb)
{
	const char *a;
	const struct kernel_symbol *b;
	a = va; b = vb;
	return strcmp(a, b->name);
}

bool hook_find_symbol_in_section(const struct symsearch *syms,
				   struct module *owner,
				   void *data)
{
	struct find_symbol_arg *fsa = data;
	struct kernel_symbol *sym;

	if (!owner) {
		sym = resolve_kallsyms_symbol(fsa->name);
		if (sym) {
			fsa->sym = sym;
			fsa->owner = NULL;
			fsa->crc = NULL;
			return true;
		}
	}

	sym = bsearch(fsa->name, syms->start, syms->stop - syms->start,
			sizeof(struct kernel_symbol), cmp_name);

	if (sym != NULL && check_symbol(syms, owner, sym - syms->start, data))
		return true;

	return false;
}
HOOK_FUNC_TEMPLATE(find_symbol_in_section);

/*************************************************************************************/

int init_symbol_resolver(void)
{
	int ret = -14;  // EFAULT
	void *find_symbol_in_section_addr = NULL;
	void *template = NULL;

	rwlock_init(&ksyms_cache_hashtable_lock);
	find_symbol_in_section_addr = (void *)find_func("find_symbol_in_section");

	if (!find_symbol_in_section_addr) {
		goto out;
	} 

	template = GET_TEMPLATE_ADDERSS(find_symbol_in_section);
	if (hijack_target_prepare(find_symbol_in_section_addr, template, NULL)) {
		goto out;
	}
	if (hijack_target_enable(find_symbol_in_section_addr)) {
		goto out;
	}
	ret = 0;
out:
	return ret;
}