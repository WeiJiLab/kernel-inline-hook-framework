#include <linux/module.h>
#include <linux/printk.h>
#include "hook_framework.h"

MODULE_AUTHOR("Liu Tao <ltao@redhat.com>");
MODULE_LICENSE("GPL");

extern int hook_fuse_open_init(void);
extern int hook_vfs_open_init(void);
extern int hook_vfs_read_init(void);
extern void hook_fuse_open_exit(void);
extern void hook_vfs_open_exit(void);
extern void hook_vfs_read_exit(void);

static int __init test_hookframe_init(void)
{
	int ret = -EFAULT;

	hook_fuse_open_init();
	if (hook_vfs_open_init())
		goto out;
	if (hook_vfs_read_init())
		goto out;
	return 0;

out:
	hook_fuse_open_exit();
	hook_vfs_open_exit();
	hook_vfs_read_exit();
	return ret;
}

static void __exit test_hookframe_exit(void)
{
	hijack_target_disable_all(true);
	printk(KERN_ALERT"unload hook framework test!\n");
}

module_init(test_hookframe_init);
module_exit(test_hookframe_exit);