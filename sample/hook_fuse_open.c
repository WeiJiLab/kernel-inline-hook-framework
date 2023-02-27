#include "include/common_data.h"
#include "hook_framework.h"
#include <linux/fs.h>
#include <linux/printk.h>

HOOK_FUNC_TEMPLATE(fuse_open_common);
int hook_fuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	char *origin_fuse_open_common;

	printk(KERN_ALERT"in hooked fuse_open_common\n");
	origin_fuse_open_common = GET_CODESPACE_ADDERSS(fuse_open_common);
	return ((int (*)(struct inode *, struct file *, bool))origin_fuse_open_common)(inode, file, isdir);
}