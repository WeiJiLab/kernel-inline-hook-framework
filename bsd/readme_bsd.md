## Usage ##

```
$ make	# to build hookFrame.ko
$ kldload ./hookFrame.ko
$ kldunload hookFrame.ko
```

#### Dev #####

Unlike linux, only one hookFrame.ko will be generated, which contains both
inline hook framework and customized hook targets.

#### Runtime #####

Unlike linux, /proc/hook_targets interface has not been implemented, so users
cannot enable/disable hooks by cmd echo. After ko file loaded successfully,
there will be similar outputs in console as presented in the demo.

## Limits ##

[Distorm](https://github.com/gdabah/distorm) is integrated for x86_64 support, the credit goes to the original authors.

## Usecase ##

Hack FreeBSD kernel at your own risk.
