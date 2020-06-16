#include <linux/module.h>
#include "include/klog.h"

MODULE_AUTHOR("Liu Tao <taobliu@thoughtworks.com>");
MODULE_LICENSE("GPL");

extern int init_symbol_resolver(void);
extern int init_stack_safety_check(void);
extern int init_hijack_operation(void);
extern int init_write_map_page(void);
extern int init_proc_interface(void);
extern void remove_proc_interface(void);
extern void hijack_target_disable_all(bool);

static int __init hook_framework_init(void)
{
    int ret = 0;
    loginfo("load hook framework!\n");
    ret = init_write_map_page();
    if (ret) {
        goto out;
    }
    ret = init_stack_safety_check();
    if (ret) {
        goto out;
    }
    ret = init_hijack_operation();
    if (ret) {
        goto out;
    }
    ret = init_proc_interface();
    if (ret) {
        goto out;
    }
    ret = init_symbol_resolver();
out:
    return ret;
}

static void __exit hook_framework_exit(void)
{
    loginfo("unload hook framework!\n");
    hijack_target_disable_all(true);
    remove_proc_interface();
}

module_init(hook_framework_init);
module_exit(hook_framework_exit);