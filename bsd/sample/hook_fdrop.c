#include "include/common_data.h"
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/file.h>
#include <sys/vnode.h>

HOOK_FUNC_TEMPLATE(_fdrop);
int hook__fdrop(struct file *fp, struct thread *td);
int hook__fdrop(struct file *fp, struct thread *td)
{
	char *fullpath = NULL;
	char *freepath = NULL;
	int error = 0;
	char *origin__fdrop = GET_CODESPACE_ADDERSS(_fdrop);

	error = vn_fullpath_global(fp->f_vnode, &fullpath, &freepath);
	if (error)
		goto out;
	printf("Reading %s\n", fullpath);

	if (freepath != NULL)
		free(freepath, M_TEMP);
out:
	return ((int (*)(struct file *, struct thread *))
		origin__fdrop)(fp, td);
}

void *_fdrop_fn = NULL;

bool hook__fdrop_init(void)
{
	_fdrop_fn = find_func("_fdrop");
	if (!_fdrop_fn)
		goto out;

	if (hijack_target_prepare(_fdrop_fn, GET_TEMPLATE_ADDERSS(_fdrop),
					GET_CODESPACE_ADDERSS(_fdrop))) {
		printf("_fdrop prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(_fdrop_fn)) {
		printf("_fdrop enable error!\n");
		goto out;
	}
	return 0;
out:
	hijack_target_disable_all(true);
	return 1;
}

void hook__fdrop_exit(void)
{
	hijack_target_disable(_fdrop_fn, true);
}