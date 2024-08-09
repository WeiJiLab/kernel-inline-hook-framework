#include "include/common_data.h"
#include "hook_framework.h"
#include <linux/fs.h>
#include <linux/printk.h>

HOOK_FUNC_TEMPLATE(fuse_open);
int hook_fuse_open(struct inode *inode, struct file *file)
{
	char *origin_fuse_open;

	printk(KERN_ALERT"in hooked fuse_open\n");
	origin_fuse_open = GET_CODESPACE_ADDERSS(fuse_open);
	return ((int (*)(struct inode *, struct file *))origin_fuse_open)(inode, file);
}