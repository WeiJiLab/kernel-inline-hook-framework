#include <linux/module.h>

MODULE_AUTHOR("Liu Tao <taobliu@thoughtworks.com>");
MODULE_LICENSE("GPL");

extern int init_symbol_resolver(void);
extern void init_stack_safety_check(void);
extern int init_hijack_operation(void);
extern int init_write_map_page(void);
extern int init_proc_interface(void);
extern void remove_proc_interface(void);
extern void hijack_target_disable_all(bool);

static int __init hook_framework_init(void)
{
    int ret = 0;
    ret = init_write_map_page();
    if (ret) {
        goto out;
    }
    init_stack_safety_check();
    ret = init_hijack_operation();
    if (ret) {
        goto out;
    }
    ret = init_proc_interface();
    if (ret) {
        goto out;
    }
    ret = init_symbol_resolver();
    if (ret) {
        goto out;
    }
    printk(KERN_ALERT"load hook framework success!\n");
    return ret;
out:
    printk(KERN_ALERT"load hook framework fail!\n");
    return ret;
}

static void __exit hook_framework_exit(void)
{
    printk(KERN_ALERT"unload hook framework!\n");
    hijack_target_disable_all(true);
    remove_proc_interface();
}

module_init(hook_framework_init);
module_exit(hook_framework_exit);