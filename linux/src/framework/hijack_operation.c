#include <linux/kernel.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#include "include/common_data.h"

extern int hook_write_range(void *, void *, int);
extern int stack_activeness_safety_check(unsigned long, unsigned long);
extern void fill_long_jmp(void *, void *);
extern bool check_target_can_hijack(void *);
extern void *stack_trace_save_tsk_ptr;

DEFINE_HASHTABLE(all_hijack_targets, DEFAULT_HASH_BUCKET_BITS);
static DECLARE_RWSEM(hijack_targets_hashtable_lock);
int (*kallsyms_lookup_size_offset_ptr)(unsigned long,
    unsigned long *, unsigned long *) = NULL;
static char name_buf[KSYM_NAME_LEN];

inline int fill_hook_template_code_space(void *hook_template_code_space, 
    void *target_code, void *return_addr)
{
    unsigned char tmp_code[HIJACK_SIZE * 2] = {0};
    memcpy(tmp_code, target_code, HIJACK_SIZE);
    if (fill_nop_for_code_space(tmp_code, target_code)) {
        return -1;
    }
    fill_long_jmp(tmp_code + HIJACK_SIZE, return_addr);
    return hook_write_range(hook_template_code_space, tmp_code, sizeof(tmp_code));
}

struct do_hijack_struct {
	void *dest;
	void *source;
	void *hook_func;
};

/*
 * -3: write hook fail
 * -2: stack within hook area(cannot write hook, retry later)
 * -1: stack within hook_func area(can write hook, retry later)
 *  0: success(can release memory immediately)
*/
__nocfi int do_hijack_target(void *data)
{
	void *dest = ((struct do_hijack_struct *)data)->dest;
	void *source = ((struct do_hijack_struct *)data)->source;
	void *hook_func = ((struct do_hijack_struct *)data)->hook_func;
	int ret = 0;

	/*if CONFIG_STACKTRACE not enabled, skip stack safety check*/
	if (!stack_trace_save_tsk_ptr)
		goto hook_write;

	ret = stack_activeness_safety_check((unsigned long)dest,
					(unsigned long)hook_func);
	if (ret == -2)
		goto out;
hook_write:
	ret = hook_write_range(dest, source, HIJACK_SIZE) ? -3 : ret;
out:
	return ret;
}

__nocfi bool check_function_length_enough(void *target)
{
    unsigned long symbolsize, offset;
    unsigned long pos;
    pos = (*kallsyms_lookup_size_offset_ptr)((unsigned long)target, &symbolsize, &offset);
    if (pos && symbolsize >= HIJACK_SIZE + offset) {
        return true;
    } else {
        return false;
    }
}

int show_all_hook_targets(struct seq_file *p, void *v)
{
    int bkt;
    struct sym_hook *sa = NULL;
    struct hlist_node *tmp;

    down_read(&hijack_targets_hashtable_lock);
    hash_for_each_safe(all_hijack_targets, bkt, tmp, sa, node) {
        memset(p->private, 0, KSYM_NAME_LEN);
        sprint_symbol_no_offset((char *)(p->private), (unsigned long)(sa->target));
        seq_printf(p, "%s %d\n", (char *)(p->private), sa->enabled);
    }
    up_read(&hijack_targets_hashtable_lock);
    return 0;
}

int hijack_target_prepare (void *target, void *hook_dest,
		void *hook_template_code_space, void *hook_func)
{
    struct sym_hook *sa = NULL;
    uint32_t ptr_hash;
    int ret = 0;

    target += HOOK_TARGET_OFFSET;
    ptr_hash = jhash_pointer(target);

    /*first, target function should longer than HIJACK_SIZE*/
    if (!check_function_length_enough(target)) {
        printk(KERN_ALERT"%lx short than hijack_size %d, cannot hijack...\n",
			(unsigned long)target, HIJACK_SIZE);
        ret = -1;
        goto out;
    }

    /*second, not contain unhookable instructions*/
    if (hook_template_code_space && !check_target_can_hijack(target)) {
	hook_template_code_space += CODE_SPACE_OFFSET;
        printk(KERN_ALERT"%lx contains instruction which cannot hijack...\n",
			(unsigned long)target);
        ret = -1;
        goto out;
    }

    /*third, target cannot repeat*/
    down_read(&hijack_targets_hashtable_lock);
    hash_for_each_possible(all_hijack_targets, sa, node, ptr_hash) {
        if (target == sa->target) {
            up_read(&hijack_targets_hashtable_lock);
            printk(KERN_ALERT"%lx has been prepared, skip...\n", (unsigned long)target);
            ret = -1;
            goto out;
        }
    }
    up_read(&hijack_targets_hashtable_lock);

    /*check passed, now to allocation*/
    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa) {
        printk(KERN_ALERT"No enough memory to hijack %lx\n", (unsigned long)target);
        ret = -1;
        goto out;
    }

    sa->target = target;
    memcpy(sa->target_code, target, HIJACK_SIZE);
    sa->hook_dest = hook_dest;
    sa->hook_template_code_space = hook_template_code_space;
    sa->hook_func = hook_func;
    sa->template_return_addr = target
#ifdef _ARCH_ARM64_
    + HIJACK_SIZE - 1 * INSTRUCTION_SIZE;
#endif

#ifdef _ARCH_ARM_
    + HIJACK_SIZE;
#endif

#if defined(_ARCH_X86_64_) || defined(_ARCH_X86_)
    + LONG_JMP_CODE_LEN - 1;
#endif

#ifdef _ARCH_POWERPC_
    + HIJACK_SIZE;
#endif
    sa->enabled = false;

    down_write(&hijack_targets_hashtable_lock);
    hash_add(all_hijack_targets, &sa->node, ptr_hash);
    up_write(&hijack_targets_hashtable_lock);

out:
    return ret;
}
EXPORT_SYMBOL(hijack_target_prepare);

int hijack_target_enable(void *target)
{
    struct sym_hook *sa;
    struct hlist_node *tmp;
    uint32_t ptr_hash;
    int ret = -1;
    unsigned char source_code[HIJACK_SIZE] = {0};
    struct do_hijack_struct do_hijack_struct;
    
    target += HOOK_TARGET_OFFSET;
    ptr_hash = jhash_pointer(target);
    do_hijack_struct = (struct do_hijack_struct ) {
        .dest = target,
        .source = source_code,
    };

    down_write(&hijack_targets_hashtable_lock);
    hash_for_each_possible_safe(all_hijack_targets, sa, tmp, node, ptr_hash) {
        if (sa->target == target) {
            if (sa->enabled == false) {
                if (sa->hook_template_code_space && fill_hook_template_code_space(
                    sa->hook_template_code_space, sa->target_code, sa->template_return_addr)) {
                    goto out;
                }
                memcpy(source_code, sa->target_code, HIJACK_SIZE);
                fill_long_jmp(source_code, sa->hook_dest);
                if ((ret = fill_nop_for_target(source_code, sa->target)))
                    goto out;
		do_hijack_struct.hook_func = sa->hook_func;
                if (!(ret = stop_machine(do_hijack_target, &do_hijack_struct, NULL))) {
                    sa->enabled = true;
                }
            } else {
                printk(KERN_ALERT"%lx has been hijacked, skip...\n", (unsigned long)(sa->target));
                ret = 0;
            }
            goto out;
        }
    }
    printk(KERN_ALERT"%lx not been prepared, skip...\n", (unsigned long)target);
out:
    up_write(&hijack_targets_hashtable_lock);

    return ret;
}
EXPORT_SYMBOL(hijack_target_enable);

int hijack_target_disable(void *target, bool need_remove)
{
	struct sym_hook *sa;
	struct hlist_node *tmp;
	uint32_t ptr_hash;
	int ret = -1;
	struct do_hijack_struct do_hijack_struct;

	target += HOOK_TARGET_OFFSET;
	ptr_hash = jhash_pointer(target);
	do_hijack_struct = (struct do_hijack_struct) {
		.dest = target
	};

	down_write(&hijack_targets_hashtable_lock);
	hash_for_each_possible_safe(all_hijack_targets, sa, tmp, node, ptr_hash) {
		if (sa->target == target) {
			sprint_symbol_no_offset(name_buf, (unsigned long)(sa->target));
			do_hijack_struct.source = sa->target_code;
			do_hijack_struct.hook_func = sa->hook_func;
			ret = stop_machine(do_hijack_target, &do_hijack_struct, NULL);
			switch (ret) {
			case 0:
			case -1:
				sa->enabled = false;
				break;
			case -2:
			case -3:
				break;
			default:
				printk(KERN_ALERT"Unknown exit value: %d\n", ret);
				break;
			}
			if (sa->enabled == false)
				printk(KERN_ALERT"%s has been disabled\n", name_buf);

			if (need_remove && !ret) {
				printk(KERN_ALERT"remove hijack target %s\n", name_buf);
				hash_del(&sa->node);
				kfree(sa);
			}
			goto out;
		}
	}
	printk(KERN_ALERT"%lx not been prepared, skip...\n", (unsigned long)target);
out:
	up_write(&hijack_targets_hashtable_lock);

	return ret;
}
EXPORT_SYMBOL(hijack_target_disable);

void hijack_target_disable_all(bool need_remove)
{
	struct sym_hook *sa;
	struct hlist_node *tmp;
	int bkt;
	bool retry;
	struct do_hijack_struct do_hijack_struct;
	int ret;

	do {
		retry = false;
		down_write(&hijack_targets_hashtable_lock);
		hash_for_each_safe(all_hijack_targets, bkt, tmp, sa, node) {
			do_hijack_struct.dest = sa->target;
			do_hijack_struct.source = sa->target_code;
			do_hijack_struct.hook_func = sa->hook_func;
			ret = stop_machine(do_hijack_target, &do_hijack_struct, NULL);
			switch (ret) {
			case 0:
				sa->enabled = false;
				break;
			case -1:
				sa->enabled = false;
				retry = true;
				break;
			case -2:
			case -3:
				retry = true;
				break;
			default:
				printk(KERN_ALERT"Unknown exit value: %d\n", ret);
				break;
			}
			if (need_remove && !ret) {
				hash_del(&sa->node);
				kfree(sa);		
			}
		}
		up_write(&hijack_targets_hashtable_lock);
	} while(retry && (msleep(1000), true));

	printk(KERN_ALERT"all hijacked target disabled%s\n", need_remove ?" and removed":"");
	return;
}
EXPORT_SYMBOL(hijack_target_disable_all);

/************************************************************************************/

int init_hijack_operation(void)
{
    kallsyms_lookup_size_offset_ptr = find_func("kallsyms_lookup_size_offset");
    if (kallsyms_lookup_size_offset_ptr) {
        return 0;
    } else {
        return -14;
    }
}