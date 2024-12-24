#include "include/common_data.h"
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

HOOK_FUNC_TEMPLATE(sys_openat);
int hook_sys_openat(struct thread *td, struct openat_args *uap);
int hook_sys_openat(struct thread *td, struct openat_args *uap)
{
	printf("In replaced sys_openat\n");
	return (kern_openat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
		uap->mode));
}

void *sys_openat_fn = NULL;

bool hook_sys_openat_init(void)
{
	sys_openat_fn = find_func("sys_openat");
	if (!sys_openat_fn)
		goto out;

	if (hijack_target_prepare(sys_openat_fn, GET_TEMPLATE_ADDERSS(sys_openat), NULL)) {
		printf("sys_openat prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(sys_openat_fn)) {
		printf("sys_openat enable error!\n");
		goto out;
	}
	return 0;
out:
	hijack_target_disable_all(true);
	return 1;
}

void hook_sys_openat_exit(void)
{
	hijack_target_disable(sys_openat_fn, true);
}
