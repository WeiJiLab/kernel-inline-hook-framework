## Usage ##

```
$ make	# to build hookFrame.ko
$ kldload ./hookFrame.ko
$ kldunload hookFrame.ko
$ echo "sys_openat 0" > /dev/hook_targets #Disable sys_openat's hook
$ echo "sys_openat 1" > /dev/hook_targets #Enable sys_openat's hook
```

#### Dev #####

Unlike linux, only one hookFrame.ko will be generated, which contains both
inline hook framework and customized hook targets.

#### Runtime #####

"/dev/hook_targets" interface acts the same as "/proc/hook_targets" in linux,
by which users can enable/disable hook functions by cmd echo. After ko file
loaded successfully, there will be similar outputs in console as presented in
the demo.

## Limits ##

[Distorm](https://github.com/gdabah/distorm) is integrated for x86_64 support, the credit goes to the original authors.

## Usecase ##

Hack FreeBSD kernel at your own risk.
