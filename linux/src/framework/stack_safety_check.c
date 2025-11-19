#include<linux/stacktrace.h>
#include<linux/kernel.h>
#include<linux/sched.h>
#include<linux/printk.h>
#include "include/common_data.h"

#define MAX_STACK_TRACE_DEPTH 64
unsigned int (*stack_trace_save_tsk_ptr)(struct task_struct *,
	unsigned long *, unsigned int, unsigned int) = NULL;

static unsigned long entries[MAX_STACK_TRACE_DEPTH];
static unsigned int nr_entries;

extern int (*kallsyms_lookup_size_offset_ptr)(unsigned long,
    unsigned long *, unsigned long *);

inline int check_address_in_stack(unsigned long addr, unsigned long stack_addr,
				unsigned long hook_func)
{
	int ret = 0;
	unsigned long symbolsize = 0, offset = 0;

	if (stack_addr >= addr && stack_addr < addr + HIJACK_SIZE) {
		ret = -16; //EBUSY
		goto out;
	}
	if (hook_func && kallsyms_lookup_size_offset_ptr) {
		if (!kallsyms_lookup_size_offset_ptr(hook_func, &symbolsize, &offset)) {
			goto out;
		}
		if (stack_addr >= hook_func - offset &&
		    stack_addr < hook_func - offset + symbolsize) {
			ret = -16; //EBUSY
		}
	}
out:
	return ret;
}

/*
* referenced from https://github.com/dynup/kpatch/blob/master/kmod/core/core.c
*/
__nocfi int stack_activeness_safety_check(unsigned long addr, unsigned long hook_func)
{
	struct task_struct *g, *t;
	int ret = 0;
	int i;

	for_each_process_thread(g, t) {
		nr_entries = (*stack_trace_save_tsk_ptr)
				(t, entries, MAX_STACK_TRACE_DEPTH, 0);
		for (i = 0; i < nr_entries; i++) {
			ret = check_address_in_stack(addr, entries[i], hook_func);
			if (ret)
				goto out;
		}
	}

out:
	if (ret) {
		printk(KERN_ALERT"Wait for PID: %d Comm: %.20s\n", t->pid, t->comm);
		for (i = 0; i < nr_entries; i++) {
			printk(KERN_ALERT"  [<%lx>] %pB\n", entries[i], (void *)entries[i]);
		}
	}
	return ret;
}

void init_stack_safety_check(void)
{
	stack_trace_save_tsk_ptr = find_func("stack_trace_save_tsk");
	if (!stack_trace_save_tsk_ptr) {
		printk(KERN_ALERT"Your kernel should be CONFIG_STACKTRACE,"
			" skip stack safety check and use as your risk!!!\n");
	}
}
