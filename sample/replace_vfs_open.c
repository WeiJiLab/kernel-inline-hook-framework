#include "include/common_data.h"
#include "hook_framework.h"
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/dcache.h>

extern struct inode *d_backing_inode(const struct dentry *upper);

extern int do_dentry_open(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *));

HOOK_FUNC_TEMPLATE(vfs_open);
int hook_vfs_open(const struct path *path, struct file *file)
{
	printk(KERN_ALERT"in replaced vfs_open\n");
	file->f_path = *path;
	return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
}