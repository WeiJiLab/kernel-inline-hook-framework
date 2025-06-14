#include "include/common_data.h"
#include "hook_framework.h"
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

ssize_t hook_vfs_read(struct file *, char __user *, size_t, loff_t *);

/* Must pass the origin_function_name to HOOK_FUNC_TEMPLATE() */
HOOK_FUNC_TEMPLATE(vfs_read);

/* The hook function name must be "hook_ + origin_function_name" */
__nocfi ssize_t hook_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	char *path_buffer = NULL;
	char *result = NULL;

	/*
	* To resume the original function, get the original function address
	* by GET_CODESPACE_ADDERSS(), which must pass the origin_function_name
	* to it.
	*/
	char *origin_vfs_read = GET_CODESPACE_ADDERSS(vfs_read);

	path_buffer = kmalloc(512, GFP_KERNEL);
	if (!path_buffer)
		goto out;

	result = d_path(&file->f_path, path_buffer, 512);
	if (!IS_ERR(result)) {
		if (!strnstr(result, "/dev/kmsg", 512 - (result - path_buffer)) && 
		    !strnstr(result, "[timerfd]", 512 - (result - path_buffer)) &&
		    !strnstr(result, "/proc/kmsg", 512 - (result - path_buffer)) &&
		    !strnstr(result, "/run/log", 512 - (result - path_buffer)) &&
		    !strnstr(result, "/var/log", 512 - (result - path_buffer)))
			printk(KERN_ALERT"reading %s\n", result);
	}
	kfree(path_buffer);
out:
	return ((ssize_t (*)(struct file *file, char __user *buf, size_t count, loff_t *pos))origin_vfs_read)(file, buf, count, pos);
}

static void *vfs_read_fn = NULL;

int hook_vfs_read_init(void)
{
	int ret = -EFAULT;

	vfs_read_fn = (void *)find_func("vfs_read");
	if (!vfs_read_fn)
		goto out;

	/*
	* template address is the trampoline where kernel function been hijacked to,
	* codespace address is the original kernel function which been hijacked and repositioned to resume.
	* If you want to replace the whole function, then leave the 3rd parameter of "hijack_target_prepare"
	* to NULL.
	* If you only want to insert your hook before or after a certain function, then leave it to be
	* "GET_CODESPACE_ADDERSS(xx_func)"
	*/

	/*
	  For powerpc, function resume is not supported, currently only function
	  replacement is supported.
	*/
#ifndef _ARCH_POWERPC_
	if (hijack_target_prepare(vfs_read_fn, GET_TEMPLATE_ADDERSS(vfs_read), GET_CODESPACE_ADDERSS(vfs_read))) {
		printk(KERN_ALERT"vfs_read prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_read_fn)) {
		printk(KERN_ALERT"vfs_read enable error!\n");
		goto out;
	}
#endif
	return 0;

out:
	hijack_target_disable(vfs_read_fn, true);
	return ret;
}

void hook_vfs_read_exit(void)
{
	hijack_target_disable(vfs_read_fn, true);
}
