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
__nocfi int hook_vfs_open(const struct path *path, struct file *file)
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

static void *vfs_open_fn = NULL;

int hook_vfs_open_init(void)
{
	int ret = -EFAULT;

	vfs_open_fn = (void *)find_func("vfs_open");
	if (!vfs_open_fn)
		goto out;

	/*
	* We will relace the original vfs_open with hook_vfs_open, so there is no
	* need to resume to the original vfs_open, therefore leave the 3rd
	* arguement to be NULL.
	*/
	if (hijack_target_prepare(vfs_open_fn, GET_TEMPLATE_ADDERSS(vfs_open), NULL,
				GET_HOOK_FUNC_ADDRESS(vfs_open))) {
		printk(KERN_ALERT"vfs_open prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_open_fn)) {
		printk(KERN_ALERT"vfs_open enable error!\n");
		goto out;
	}
	return 0;
out:
	hijack_target_disable(vfs_open_fn, true);
	return ret;
}

void hook_vfs_open_exit(void)
{
	hijack_target_disable(vfs_open_fn, true);
}