#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "common_data.h"

static int len,temp;

static char *msg;
static char *dirname="driver/mydriver";
static char *dirname2="settings";
struct proc_dir_entry *subdirparent;
struct proc_dir_entry *parent;
struct proc_dir_entry *parent2;
static ssize_t read_proc(struct file *filp,char *buf,size_t count,loff_t *offp )
{
    if(count>temp){count=temp;}
    temp=temp-count;
    copy_to_user(buf,msg, count);
    if(count==0){temp=len;}

    return count;
}

static ssize_t write_proc(struct file *filp,const char *buf,size_t count,loff_t *offp)
{
    copy_from_user(msg,buf,count);
    len=count;
    temp=len;

    return count;
}

struct file_operations proc_fops = {
    read: read_proc,
    write: write_proc
};

static void create_new_proc_entry(void)
{
    parent = proc_mkdir(dirname, NULL);
    parent2 = proc_mkdir(dirname2,parent);
    proc_create("private_setting",0644,parent2,&proc_fops);
    msg=kmalloc(GFP_KERNEL,10*sizeof(char));
}


static int proc_init (void)
{
 create_new_proc_entry();
 return 0;
}

static void proc_cleanup(void)
{
    remove_proc_entry("private_setting",parent2);
    remove_proc_entry(dirname2,parent);
    remove_proc_entry(dirname,NULL);
}

MODULE_LICENSE("GPL"); 
module_init(proc_init);
module_exit(proc_cleanup);



struct proc_dir_entry *top_entry = NULL;
#define BUFFERSIZE 8

static ssize_t read_entry(struct file *filp, char *buf, size_t count, loff_t *offp )
{
    char buffer[BUFFERSIZE] = {0};
    const char *file_name = filp->f_path.dentry->d_iname;
    void *addr = NULL;
    if (!file_name || !(addr = (void *)find_func(file_name))) {
        return -1;
    }
    buffer[0] = get_hijack_target_status(addr) ? "1" : "0";
    copy_to_user(buf, buffer, 1);
    return 0;
}

static ssize_t write_entry(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
    char buffer[BUFFERSIZE] = {0};
    const char *file_name = filp->f_path.dentry->d_iname;
    void *addr = NULL;
    if (!file_name || !(addr = (void *)find_func(file_name))) {
        return -1;
    }
    copy_from_user(buffer, buf, BUFFERSIZE > count ? count : BUFFERSIZE);
    switch (buffer[0]) {
        case "1":
            hijack_target_enable(addr);
            break;
        case "0":
            hijack_target_disable(addr, false);
            break;
        default:
            break;
    }
    return 0;
}

static int create_top_entry(void)
{
    top_entry = proc_mkdir("hijack_functions", NULL);
    if (!top_entry) {
        logerror("Fail to create top proc entry!\n");
        return -1;
    }
    return 0;
}

static int update_entry()
{

}

