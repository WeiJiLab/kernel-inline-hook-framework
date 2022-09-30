#include "include/common_data.h"
#include <linux/kernel.h>
#include <linux/kprobes.h>

unsigned long (*kallsyms_lookup_name_ptr)(const char *) = NULL;

int init_symbol_resolver(void)
{
	int ret;
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