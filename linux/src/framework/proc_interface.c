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

static ssize_t hook_targets_write(struct file *file, const char __user *buf, size_t count, loff_t *offp)
{
    char *string_start, *sep, *val_start;
    long val;
    void *target;
    int ret;
    char *buffer = ((struct seq_file *)file->private_data)->private;

    memset(buffer, 0, KSYM_NAME_LEN);
    if (copy_from_user(buffer, buf, 
        count > KSYM_NAME_LEN ? KSYM_NAME_LEN : count)) {
        return -EFAULT;
    }
    string_start = strim(buffer);
    if (!(sep = strnchr(string_start, KSYM_NAME_LEN, ' '))) {
        return -EFAULT;
    }
    *sep++ = '\0';
    val_start = strim(sep);
    if (kstrtol(val_start, 10, &val) < 0) {
        return -EFAULT;
    }

    if (!(target = find_func(string_start))) {
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
    void *buffer = kzalloc(KSYM_NAME_LEN, GFP_KERNEL);
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

static struct proc_ops proc_ops = {
	.proc_open		= hook_targets_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= hook_targets_release,
	.proc_write 		= hook_targets_write,
};

int init_proc_interface(void)
{
    if (!proc_create("hook_targets", 0600, NULL, &proc_ops))
        return -1;
    return 0;
}

void remove_proc_interface(void)
{
    remove_proc_entry("hook_targets", NULL);
}
