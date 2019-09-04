#include <linux/module.h>
#include "include/klog.h"

MODULE_AUTHOR("Liu Tao <taobliu@thoughtworks.com>");
MODULE_LICENSE("GPL");

extern int init_symbol_resolver(void);
extern int init_stack_safety_check(void);
extern int init_hijack_operation(void);
extern int init_write_map_page(void);

static int __init saic_framework_init(void)
{
    int ret = 0;
    loginfo("load security enhencement framework!\n");
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
    ret = init_symbol_resolver();
    if (ret) {
        goto out;
    }
out:
    return ret;
}

static void __exit saic_framework_exit(void)
{
    loginfo("unload security enhencement framework!\n");
}

module_init(saic_framework_init);
module_exit(saic_framework_exit);