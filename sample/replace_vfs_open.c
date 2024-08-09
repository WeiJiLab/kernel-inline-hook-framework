#include "include/common_data.h"
#include "hook_framework.h"
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/fsnotify.h>

extern int do_dentry_open(struct file *f,
			  int (*open)(struct inode *, struct file *));

HOOK_FUNC_TEMPLATE(vfs_open);
int hook_vfs_open(const struct path *path, struct file *file)
{
	int ret;

	printk(KERN_ALERT"in replaced vfs_open\n");
	file->f_path = *path;
	ret = do_dentry_open(file, NULL);
	if (!ret) {
		/*
		 * Once we return a file with FMODE_OPENED, __fput() will call
		 * fsnotify_close(), so we need fsnotify_open() here for
		 * symmetry.
		 */
		fsnotify_open(file);
	}
	return ret;
}