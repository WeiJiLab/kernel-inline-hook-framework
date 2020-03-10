#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "include/common_data.h"

extern int hijack_target_enable(void *);
extern int hijack_target_disable(void *, bool);

static ssize_t hook_targets_write(struct file *file, const char *buf, size_t count, loff_t *offp)
{
    char *string_start, *sep, *val_start;
    long val;
    void *target;
    int ret;
    char *buffer = ((struct seq_file *)file->private_data)->private;

    memset(buffer, 0, MAX_KSYM_NAME_LEN);
    if (copy_from_user(buffer, buf, 
        count > MAX_KSYM_NAME_LEN ? MAX_KSYM_NAME_LEN : count)) {
        return -EFAULT;
    }
    string_start = strim(buffer);
    if (!(sep = strnchr(string_start, MAX_KSYM_NAME_LEN, ' '))) {
        return -EFAULT;
    }
    *sep++ = '\0';
    val_start = strim(sep);
    if (kstrtol(val_start, 10, &val) < 0) {
        return -EFAULT;
    }

    if (!(target = (void *)kallsyms_lookup_name(string_start))) {
        return -EFAULT;
    }

    switch (val) {
    case 0:
        ret = hijack_target_disable(target, false);
        break;
    case 1:
        ret = hijack_target_enable(target);
        break;
    default:
        return -EFAULT;
    }
    
    return ret < 0 ? -EFAULT : count;
}

extern int show_all_hook_targets(struct seq_file *, void *);

static int hook_targets_open(struct inode *inode, struct file *file)
{
    void *buffer = kzalloc(MAX_KSYM_NAME_LEN, GFP_KERNEL);
    if (!buffer) {
        return -ENOMEM;
    }
	return single_open(file, show_all_hook_targets, buffer);
}

static int hook_targets_release(struct inode *inode, struct file *file)
{
    struct seq_file *sqf= (struct seq_file *)file->private_data;
    kfree(sqf->private);
    sqf->private = NULL;
    return single_release(inode, file);
}

static const struct file_operations proc_operations = {
	.open		= hook_targets_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= hook_targets_release,
	.write 		= hook_targets_write,
};

int init_proc_interface(void)
{
    if (!proc_create("hook_targets", 0600, NULL, &proc_operations))
        return -1;
    return 0;
}
