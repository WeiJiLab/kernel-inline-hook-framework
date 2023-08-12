#include "include/common_data.h"
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <uapi/linux/elf.h>
#include <linux/mm_types.h>
#include <linux/wait.h>
#include <linux/compiler.h>
#include <uapi/linux/elf-em.h>
#include <linux/version.h>

struct load_info {
	const char *name;
	/* pointer to module in temporary copy, freed at end of load_module() */
	struct module *mod;
	Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
   #if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
	struct _ddebug_info dyndbg;
   #endif
#else
	struct _ddebug *debug;
	unsigned int num_debug;
#endif
	bool sig_ok;

#ifdef CONFIG_KALLSYMS
	unsigned long mod_kallsyms_init_off;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
  #ifdef CONFIG_MODULE_DECOMPRESS
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
      #ifdef CONFIG_MODULE_STATS
        unsigned long compressed_len;
      #endif
    #endif
	struct page **pages;
	unsigned int max_pages;
	unsigned int used_pages;
  #endif
#endif
	struct {
		unsigned int sym, str, mod, vers, info, pcpu;
	} index;
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

/******************************************************************************/

static const struct kernel_symbol *(*resolve_symbol_ptr)(struct module *,
						  const struct load_info *,
						  const char *,
						  char []) = NULL;
static struct wait_queue_head *module_wq_ptr = NULL;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *) = NULL;
extern int hijack_target_prepare(void *, void *, void *);
extern int hijack_target_enable(void *);

void *find_func(const char *name)
{
	void *ret = NULL;
	ret = (void *)kallsyms_lookup_name_ptr(name);
	if (!ret) {
		printk(KERN_ALERT"Symbol %s not found!\n", name);
	}
	return ret;
}
EXPORT_SYMBOL(find_func);

/******************************************************************************/

static inline void __percpu *mod_percpu(struct module *mod)
{
#ifdef CONFIG_SMP
	return mod->percpu;
#else
	return NULL;
#endif
}

static const struct kernel_symbol *
resolve_symbol_wait(struct module *mod,
		    const struct load_info *info,
		    const char *name)
{
	const struct kernel_symbol *ksym;
	char owner[MODULE_NAME_LEN];

	if (wait_event_interruptible_timeout(*module_wq_ptr,
			!IS_ERR(ksym = resolve_symbol_ptr(mod, info, name, owner))
			|| PTR_ERR(ksym) != -EBUSY,
					     30 * HZ) <= 0) {
		pr_warn("%s: gave up waiting for init of module %s.\n",
			mod->name, owner);
	}
	return ksym;
}

static inline unsigned long kernel_symbol_value(const struct kernel_symbol *sym)
{
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
	return (unsigned long)offset_to_ptr(&sym->value_offset);
#else
	return sym->value;
#endif
}

static bool ignore_undef_symbol(Elf_Half emachine, const char *name)
{
	/*
	 * On x86, PIC code and Clang non-PIC code may have call foo@PLT. GNU as
	 * before 2.37 produces an unreferenced _GLOBAL_OFFSET_TABLE_ on x86-64.
	 * i386 has a similar problem but may not deserve a fix.
	 *
	 * If we ever have to ignore many symbols, consider refactoring the code to
	 * only warn if referenced by a relocation.
	 */
	if (emachine == EM_386 || emachine == EM_X86_64)
		return !strcmp(name, "_GLOBAL_OFFSET_TABLE_");
	return false;
}

int hook_simplify_symbols(struct module *mod, const struct load_info *info)
{
	Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
	Elf_Sym *sym = (void *)symsec->sh_addr;
	unsigned long secbase;
	unsigned int i;
	int ret = 0;
	const struct kernel_symbol *ksym;

	for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
		const char *name = info->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			/* Ignore common symbols */
			if (!strncmp(name, "__gnu_lto", 9))
				break;

			/*
			 * We compiled with -fno-common.  These are not
			 * supposed to happen.
			 */
			pr_debug("Common symbol: %s\n", name);
			pr_warn("%s: please compile with -fno-common\n",
			       mod->name);
			ret = -ENOEXEC;
			break;

		case SHN_ABS:
			/* Don't need to do anything */
			pr_debug("Absolute symbol: 0x%08lx %s\n",
				 (long)sym[i].st_value, name);
			break;

		case SHN_LIVEPATCH:
			/* Livepatch symbols are resolved by livepatch */
			break;

		case SHN_UNDEF:
			ksym = resolve_symbol_wait(mod, info, name);
			/* Ok if resolved.  */
			if (ksym && !IS_ERR(ksym)) {
				sym[i].st_value = kernel_symbol_value(ksym);
				break;
			}

			/* Ok if weak or ignored.  */
			if (!ksym &&
			    (ELF_ST_BIND(sym[i].st_info) == STB_WEAK ||
			     ignore_undef_symbol(info->hdr->e_machine, name)))
				break;

			ret = PTR_ERR(ksym) ?: -ENOENT;

			if (ret) {
				sym[i].st_value = (Elf_Addr)find_func(name);
				if (sym[i].st_value) {
					ret = 0;
					break;
				}
			}

			pr_warn("%s: Unknown symbol %s (err %d)\n",
				mod->name, name, ret);
			break;

		default:
			/* Divert to percpu allocation if a percpu var. */
			if (sym[i].st_shndx == info->index.pcpu)
				secbase = (unsigned long)mod_percpu(mod);
			else
				secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
	}

	return ret;
}
HOOK_FUNC_TEMPLATE(simplify_symbols);

/******************************************************************************/

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
	kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))(kp.addr);
	unregister_kprobe(&kp);
	ret = 0;
out:
	return ret;
}

int init_simplify_symbols_hook(void)
{
	void *simplify_symbols_ptr;

	resolve_symbol_ptr = find_func("resolve_symbol");
	simplify_symbols_ptr = find_func("simplify_symbols");
	module_wq_ptr = find_func("module_wq");

	if (!resolve_symbol_ptr || !simplify_symbols_ptr ||
	    !module_wq_ptr)
		goto out;
	
	if (hijack_target_prepare(simplify_symbols_ptr,
				  GET_TEMPLATE_ADDERSS(simplify_symbols),
				  NULL)) {
		printk(KERN_ALERT"simplify_symbols prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(simplify_symbols_ptr)) {
		printk(KERN_ALERT"simplify_symbols enable error!\n");
		goto out;
	}

	return 0;
out:
	return -EFAULT;
}