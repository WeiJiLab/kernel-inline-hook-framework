#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/module.h>
#include "include/common_data.h"

static int free_dev = 0;
static int free_openat = 0;
static int free_dofileread = 0;

static int
hookframe_init(void)
{
	int ret;
	printf("hookFrame: loading start\n");

	if ((ret = init_hijack_operation()) != 0)
		goto fail;

	if ((ret = init_dev_interface()) != 0)
		goto fail;
	free_dev = 1;

	if ((ret = hook_sys_openat_init()) == 0)
		free_openat = 1;

	if ((ret = hook_dofileread_init()) == 0)
		free_dofileread = 1;

	printf("hookFrame: loaded\n");
	return 0;

fail:
	printf("hookFrame: load failed (%d)\n", ret);
	return ret;
}

static int
hookframe_fini(void)
{
	printf("hookFrame: unloading\n");

	if (free_dofileread)
		hook_dofileread_exit();
	if (free_openat)
		hook_sys_openat_exit();
	if (free_dev)
		remove_dev_interface();

	printf("hookFrame: unloaded\n");
	return 0;
}

static int
module_handler(struct module *m, int what, void *arg)
{
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		error = hookframe_init();
		break;

	case MOD_UNLOAD:
		error = hookframe_fini();
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

static moduledata_t hookFrame_data = {
	"hookFrame",
	module_handler,
	NULL
};

DECLARE_MODULE(hookFrame, hookFrame_data, SI_SUB_KLD, SI_ORDER_ANY);
