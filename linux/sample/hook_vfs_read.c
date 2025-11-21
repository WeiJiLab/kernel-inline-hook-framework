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

	/**
	 * arg1: the original function address which you'd like to hijack.
	 * arg2: GET_TEMPLATE_ADDERSS() is the trampoline template address
	 *       that your original function will be hijacked to firstly.
	 *       Then the trampoline will jump to your hook function.
	 * arg3: GET_CODESPACE_ADDERSS() is the new address of your original
	 *       function, if you'd like to call it later. If you will never
	 *       call the original function, simply leave it to be NULL.
	 * arg4: GET_HOOK_FUNC_ADDRESS() is your hook function address, which
	 *       is used for stack safety check when disabling the hook.
	 */
	/*
	  For powerpc, function resume is not supported, currently only function
	  replacement is supported.
	*/
#ifndef _ARCH_POWERPC_
	if (hijack_target_prepare(vfs_read_fn, GET_TEMPLATE_ADDERSS(vfs_read),
			GET_CODESPACE_ADDERSS(vfs_read), GET_HOOK_FUNC_ADDRESS(vfs_read))) {
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
