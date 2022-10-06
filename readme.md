# Overview #

## News

1) support kernel version to 5.19

2) x86_64/x86 support

## Introduction ##

Usually we want to hack a kernel function, 

1) to insert customized code before or after a certain kernel function been called, or 

2) to totally replace a function with new one. 

How can we manage that? Well it's time to bring inline hook technique to kernel space. By replacing the first few instructions of a specific function to conditionless jump, and store the original instructions to a trampoline function, we can customizing the functions calling, and do whatever we want do in the hook function. Isn't is exciting?

## Usage ##

#### Dev #####

There will be 2 kernel modules:

1) src/: The hook framework itself. In normal cases, you needn't modify its code, unless you are trying to fix bug, because we want to keep it as simple and independent to any customization. After compile, you will get hookFrame.ko.

2) sample/: The customized hook/replacement functions. Write your code here, and you can take hook_vfs_read.c, replace_vfs_open.c as reference when writing your own function. Also in module.c, you can  get a general view of how to register your function to hook framework. After compile, hookFrameTest.ko will be generated.

Sometimes you will find the vermagic of hookFrame.ko and hookFrameTest.ko different from your target kernel. You can pass the target kernel's vermagic string to make:

```
# For example:
$ sudo apt-get install bbe      # install bbe to modify vermagic string within .ko
$ make arm64 KDIR=/opt/linux-4.14.98 CROSS_COMPILE=aarch64-linux-android- vermagic="4.14.98 SMP preempt mod_unload modversions aarch64"
```

#### Runtime #####
Insert hookFrame.ko first, then insert hookFrameTest.ko. If success, you can see list of currently reading files, and strings as "in replaced vfs_open", which indicating the original kernel vfs_open and vfs_read has been hooked.

you can rmmod hookFrameTest.ko, to restore the original state. Also you can find a file: /proc/hook_targets. When cat the file, you can view the currently hooked functions list, and it's status(0 disabled, 1 enabled). You can also call the following command to change hook targets status:

```
$ echo "vfs_read 0" > /proc/hook_targets # disable vfs_read hooking
$ echo "vfs_read 1" > /proc/hook_targets # enable vfs_read hooking
```

## Limits ##
Now I bump the kernel support version to 5.19, tested in fedora36. It will not backward support the older 4.14 kernels. If you are still interested in the old kernel support, please checkout the old code from git log.

Currently it support arm32, arm64, x86 and x86_64. [Distorm](https://github.com/gdabah/distorm) is integrated for x86_64 support, the credit goes to the original authors.

In addition, in order to make hook framework work properly, target kernel's configuration CONFIG_KALLSYMS and CONFIG_KPROBES is a must.

## Bugs ##
Please report any bugs to me: liutgnu@gmail.com, also any contributions are welcomed.

## Happy Hacking !!! ##
