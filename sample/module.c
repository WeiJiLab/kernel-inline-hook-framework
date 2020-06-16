#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/errno-base.h>
#include <linux/err.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include "include/common_data.h"
#include "include/hook_framework.h"

MODULE_AUTHOR("Liu Tao <taobliu@thoughtworks.com>");
MODULE_LICENSE("GPL");

char *(*d_absolute_path_fn)(const struct path *path,
	       char *buf, int buflen) = NULL;

int (*do_dentry_open_fn)(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *)) = NULL;

extern ssize_t hook_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
extern int hook_vfs_open(const struct path *path, struct file *file);

static inline void *find_func(const char *name)
{
	void *ret = NULL;
	ret = (void *)kallsyms_lookup_name(name);
	if (!ret) {
		printk(KERN_ALERT"Symbol %s not found!", name);
	}
	return ret;
}

#define GET_CODE_ADDERSS(s) \
({  \
    void *template; \
    __asm__ volatile ("ldr %0, ="#s"_code_space\n\t":"=r"(template)); \
    template;  \
})

static int __init test_hookframe_init(void)
{
    int ret = -EFAULT;
    void *vfs_read_fn;
    void *vfs_open_fn; 

    d_absolute_path_fn = (char *(*)(const struct path *path,
	       char *buf, int buflen))kallsyms_lookup_name("d_absolute_path");
    if (!d_absolute_path_fn) {
        printk(KERN_ALERT"d_absolute_path not found!");
        ret = -EFAULT;
        goto out;
    }

    do_dentry_open_fn = (int (*)(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *)))kallsyms_lookup_name("do_dentry_open");
    if (!do_dentry_open_fn) {
        printk(KERN_ALERT"do_dentry_open not found!");
        ret = -EFAULT;
        goto out;
    }

    vfs_read_fn = (void *)find_func("vfs_read"); 
    vfs_open_fn = (void *)find_func("vfs_open"); 

	if (hijack_target_prepare(vfs_read_fn, GET_TEMPLATE_ADDERSS(vfs_read), GET_CODESPACE_ADDERSS(vfs_read))) {
        printk(KERN_ALERT"vfs_read prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_read_fn)) {
        printk(KERN_ALERT"vfs_read enable error!\n");
		goto out;
	}

	if (hijack_target_prepare(vfs_open_fn, GET_TEMPLATE_ADDERSS(vfs_open), NULL)) {
        printk(KERN_ALERT"vfs_open prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_open_fn)) {
        printk(KERN_ALERT"vfs_open enable error!\n");
		goto out;
	}
    return 0;

out:
    return ret;
}

static void __exit test_hookframe_exit(void)
{
    hijack_target_disable_all(true);
    printk(KERN_ALERT"unload security enhencement framework!\n");
}

module_init(test_hookframe_init);
module_exit(test_hookframe_exit);