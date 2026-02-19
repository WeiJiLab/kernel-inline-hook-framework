#include "include/common_data.h"
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/file.h>
#include <sys/vnode.h>

HOOK_FUNC_TEMPLATE(dofileread);
int hook_dofileread(struct thread *td, int fd, struct file *fp, struct uio *auio,
			off_t offset, int flags);
int hook_dofileread(struct thread *td, int fd, struct file *fp, struct uio *auio,
			off_t offset, int flags)
{
	char *fullpath = NULL;
	char *freepath = NULL;
	int error = 0;
	char *origin_dofileread = GET_CODESPACE_ADDERSS(dofileread);

	error = vn_fullpath_global(fp->f_vnode, &fullpath, &freepath);
	if (error)
		goto out;
	if (!strstr(fullpath, "/dev/klog"))
		printf("Reading %s\n", fullpath);

	if (freepath != NULL)
		free(freepath, M_TEMP);
out:
	return ((int (*)(struct thread *, int, struct file *, struct uio *,
			off_t, int))
		origin_dofileread)(td, fd, fp, auio, offset, flags);
}

void *dofileread_fn = NULL;

bool hook_dofileread_init(void)
{
	dofileread_fn = find_func("dofileread");
	if (!dofileread_fn)
		goto out;

	if (hijack_target_prepare(dofileread_fn, GET_TEMPLATE_ADDERSS(dofileread),
					GET_CODESPACE_ADDERSS(dofileread))) {
		printf("dofileread prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(dofileread_fn)) {
		printf("dofileread enable error!\n");
		goto out;
	}
	return 0;
out:
	hijack_target_disable(dofileread_fn, true);
	return 1;
}

void hook_dofileread_exit(void)
{
	hijack_target_disable(dofileread_fn, true);
}