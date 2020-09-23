#ifndef CONFIG_STACKTRACE
#define CONFIG_STACKTRACE
#endif
#include<linux/stacktrace.h>
#include<linux/kernel.h>
#include<linux/sched.h>
#include<linux/sched/signal.h>
#include "include/common_data.h"

#define MAC_STACK_TRACE_DEPTH 64
void (*save_stack_trace_tsk_ptr)(struct task_struct *,
    struct stack_trace *) = NULL;

static unsigned long stack_entries[MAC_STACK_TRACE_DEPTH];
static struct stack_trace trace = {
    .max_entries = ARRAY_SIZE(stack_entries),
    .entries = &stack_entries[0],
};

inline int check_address_in_stack(unsigned long addr, unsigned long stack_addr)
{
    if (stack_addr >= addr && stack_addr < addr + HIJACK_SIZE) {
        return -16; //EBUSY
    }
    return 0;
}

/*
* referenced from https://github.com/dynup/kpatch/blob/master/kmod/core/core.c
*/
int stack_activeness_safety_check(unsigned long addr)
{
    struct task_struct *g, *t;
    int ret = 0;
    int i;
    do_each_thread(g, t) {
        trace.nr_entries = 0;
        (*save_stack_trace_tsk_ptr)(t, &trace);
        if (trace.nr_entries >= trace.max_entries) {
            ret = -16; //EBUSY
            printk(KERN_ALERT"More than %d max trace entries!\n", trace.max_entries);
            goto out;
        }

        for (i = 0; i < trace.nr_entries; i++) {
            if (trace.entries[i] == ULONG_MAX)
                break;
            ret = check_address_in_stack(addr, trace.entries[i]);
            if (ret)
                goto out;
        }
    } while_each_thread(g, t);

out:
    if (ret) {
        printk(KERN_ALERT"PID: %d Comm: %.20s\n", t->pid, t->comm);
        for (i = 0; i < trace.nr_entries; i++) {
            if (trace.entries[i] == ULONG_MAX)
                break;
            printk(KERN_ALERT"  [<%pK>] %pB\n", (void *)trace.entries[i], (void *)trace.entries[i]);
        }
    }
    return ret;
}

void init_stack_safety_check(void)
{
    save_stack_trace_tsk_ptr = find_func("save_stack_trace_tsk");
    if (!save_stack_trace_tsk_ptr) {
        printk(KERN_ALERT"CONFIG_STACKTRACE may not be enabled, skip stack safety check and use as your risk!!!\n");
    }
}
