#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/module.h>
#include "include/common_data.h"

static int init(void)
{
	int ret = 0;

	printf("hookFrame loading start!\n");
	if ((ret = init_hijack_operation())) {
		goto out;
	}
	if ((ret = init_dev_interface())) {
		goto out;
	}
	if ((ret = hook_sys_openat_init())) {
		goto out;
	}
	if ((ret = hook__fdrop_init())) {
		goto out;
	}
	printf("hookFrame loaded!\n");
out:
	return ret;
}

static void exit(void)
{
	hook_sys_openat_exit();
	hook__fdrop_exit();
	remove_dev_interface();
	printf("hookFrame unloaded!\n");
}

static int
module_handler(struct module *m, int what, void *arg)
{
	switch (what) {
	case MOD_LOAD:
		if (init()) {
			printf("hookFrame load error!\n");
			exit();
			return EFAULT;
		}
		return 0;
	case MOD_UNLOAD:
		exit();
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

static moduledata_t hookFrame_data = {
	"hookFrame",
	module_handler,
	NULL
};

DECLARE_MODULE(hookFrame, hookFrame_data, SI_SUB_KLD, SI_ORDER_ANY);
