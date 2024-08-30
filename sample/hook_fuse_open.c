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

static void *fuse_open_fn = NULL;

int hook_fuse_open_init(void)
{
	int ret = -EFAULT;

	fuse_open_fn = (void *)find_func("fuse_open");
	if (!fuse_open_fn)
		goto out;

#ifndef _ARCH_POWERPC_
	/*
	* Same as hook_vfs_read(), please refer to it for code explaination.
	*/
	if (hijack_target_prepare(fuse_open_fn, GET_TEMPLATE_ADDERSS(fuse_open), GET_CODESPACE_ADDERSS(fuse_open))) {
		printk(KERN_ALERT"fuse_open prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(fuse_open_fn)) {
		printk(KERN_ALERT"fuse_open enable error!\n");
		goto out;
	}
#endif
	return 0;

out:
	hijack_target_disable(fuse_open_fn, true);
	return ret;
}

void hook_fuse_open_exit(void)
{
	hijack_target_disable(fuse_open_fn, true);
}