#include <linux/kernel.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "include/common_data.h"

extern int hook_write_range(void *, void *);
extern int stack_activeness_safety_check(unsigned long);
extern void fill_long_jmp(void *, void *);
extern bool check_target_can_hijack(void *);

DEFINE_HASHTABLE(all_hijack_targets, DEFAULT_HASH_BUCKET_BITS);
// static rwlock_t hijack_targets_hashtable_lock;
unsigned long (*get_symbol_pos_addr)
    (unsigned long, unsigned long *, unsigned long *) = NULL;

inline void fill_hook_template_code_space(void *hook_template_code_space, 
    void *target_code, void *return_addr)
{
    memcpy(hook_template_code_space, target_code, HIJACK_SIZE);
    fill_long_jmp(hook_template_code_space + HIJACK_SIZE, return_addr);
}

struct do_hijack_struct {
    void *dest;
    void *source;
};

int do_hijack_target(void *data)
{
    void *dest = ((struct do_hijack_struct *)data)->dest;
    void *source = ((struct do_hijack_struct *)data)->source;
    int ret = 0;

    if (!(ret = stack_activeness_safety_check((unsigned long)dest))) {  //no problem
        ret = hook_write_range(dest, source);
    }
    return ret;
}

bool check_function_length_enough(void *target)
{
    unsigned long symbolsize, offset;
    unsigned long pos;
    pos = (*get_symbol_pos_addr)((unsigned long)target, &symbolsize, &offset);
    if (pos && !offset && symbolsize >= HIJACK_SIZE) {
        return true;
    } else {
        return false;
    }
}

void get_all_hijack_targets(void)
{
    int bkt;
    struct sym_hook *sa = NULL;
    struct hlist_node *tmp;

    // read_lock(&hijack_targets_hashtable_lock);
    hash_for_each_safe(all_hijack_targets, bkt, tmp, sa, node) {
        loginfo("list hijack targets: %p status: %s\n", sa->target, sa->enabled ? "enabled" : "disabled");
    }
    // read_unlock(&hijack_targets_hashtable_lock);
}

int hijack_target_prepare (void *target, void *hook_dest, void *hook_template_code_space)
{
    struct sym_hook *sa = NULL;
    uint32_t ptr_hash = jhash_pointer(target);
    int ret = 0;

    /*first, target function should longer than HIJACK_SIZE*/
    if (!check_function_length_enough(target)) {
        logerror("%p short than hijack_size %d, cannot hijack...", target, HIJACK_SIZE);
        ret = -1;
        goto out;
    }

    /*second, not contain unhookable instructions*/
    if (hook_template_code_space && !check_target_can_hijack(target)) {
        logerror("%p contains instruction which cannot hijack...", target);
        ret = -1;
        goto out;
    }

    /*third, target cannot repeat*/
    // read_lock(&hijack_targets_hashtable_lock);
    hash_for_each_possible(all_hijack_targets, sa, node, ptr_hash) {
        if (target == sa->target) {
            logerror("%p has been prepared, skip...", target);
            ret = -1;
            // read_unlock(&hijack_targets_hashtable_lock);
            goto out;
        }
    }
    // read_unlock(&hijack_targets_hashtable_lock);

    /*check passed, now to allocation*/
    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa) {
        logerror("No enough memory to hijack %p\n", target);
        ret = -1;
        goto out;
    }

    sa->target = target;
    memcpy(sa->target_code, target, HIJACK_SIZE);
    sa->hook_dest = hook_dest;
    sa->hook_template_code_space = hook_template_code_space;
    sa->template_return_addr = HIJACK_SIZE - sizeof(void *) + target;
    sa->enabled = false;

    // write_lock(&hijack_targets_hashtable_lock);
    hash_add(all_hijack_targets, &sa->node, ptr_hash);
    // write_unlock(&hijack_targets_hashtable_lock);

    get_all_hijack_targets();
out:
    return ret;
}

int hijack_target_enable(void *target)
{
    struct sym_hook *sa;
    struct hlist_node *tmp;
    uint32_t ptr_hash = jhash_pointer(target);
    int ret = -1;
    unsigned char source_code[HIJACK_SIZE] = {0};
    struct do_hijack_struct do_hijack_struct = {
        .dest = target,
        .source = source_code,
    };

    // write_lock(&hijack_targets_hashtable_lock);
    hash_for_each_possible_safe(all_hijack_targets, sa, tmp, node, ptr_hash) {
        if (sa->target == target) {
            if (sa->enabled == false) {
                if (sa->hook_template_code_space) {
                    fill_hook_template_code_space(sa->hook_template_code_space,
                        sa->target_code, sa->template_return_addr);
                }
                fill_long_jmp(source_code, sa->hook_dest);
                if (!(ret = stop_machine(do_hijack_target, &do_hijack_struct, NULL))) {
                    sa->enabled = true;
                }
            } else {
                loginfo("%p has been hijacked, skip...\n", sa->target);
                ret = 0;
            }
            goto out;
        }
    }
    loginfo("%p not been prepared, skip...\n", target);
out:
    // write_unlock(&hijack_targets_hashtable_lock);

    get_all_hijack_targets();
    return ret;
}

int hijack_target_disable(void *target, bool need_remove)
{
    struct sym_hook *sa;
    struct hlist_node *tmp;
    uint32_t ptr_hash = jhash_pointer(target);
    int ret = -1;
    struct do_hijack_struct do_hijack_struct = {
        .dest = target
    };    

    // write_lock(&hijack_targets_hashtable_lock);
    hash_for_each_possible_safe(all_hijack_targets, sa, tmp, node, ptr_hash) {
        if (sa->target == target) {
            if (sa->enabled == true) {
                do_hijack_struct.source = sa->target_code;
                if (!(ret = stop_machine(do_hijack_target, &do_hijack_struct, NULL)))
                    sa->enabled = false;
            } else {
                loginfo("%p has been disabled\n", sa->target);
                ret = 0;
            }

            if (need_remove && !ret) {
                loginfo("remove hijack target %p\n", target);
                hash_del(&sa->node);
                kfree(sa);
            }
            goto out;
        }
    }
    loginfo("%p not been prepared, skip...\n", target);
out:
    // write_unlock(&hijack_targets_hashtable_lock);

    get_all_hijack_targets();
    return ret;
}

void hijack_target_disable_all(bool need_remove)
{
    struct sym_hook *sa;
    struct hlist_node *tmp;
    int bkt;
    bool retry;
    struct do_hijack_struct do_hijack_struct;

    do {
        retry = false;
        // write_lock(&hijack_targets_hashtable_lock);
        hash_for_each_safe(all_hijack_targets, bkt, tmp, sa, node) {
            if (sa->enabled == true) {
                do_hijack_struct.dest = sa->target;
                do_hijack_struct.source = sa->target_code;
                if (stop_machine(do_hijack_target, &do_hijack_struct, NULL)) {
                    retry = true;
                    continue;
                }
                sa->enabled = false;
            }
            if (need_remove) {
                hash_del(&sa->node);
                kfree(sa);
            }
        }
        // write_unlock(&hijack_targets_hashtable_lock);
    } while(retry && (msleep(1000), true));

    loginfo("all hijacked target disabled%s\n", need_remove ?" and removed":"");
    get_all_hijack_targets();
    return;
}

/************************************************************************************/

int init_hijack_operation(void)
{
    // rwlock_init(&hijack_targets_hashtable_lock);
    get_symbol_pos_addr = find_func("get_symbol_pos");
    if (get_symbol_pos_addr) {
        return 0;
    } else {
        return -14;
    }
}