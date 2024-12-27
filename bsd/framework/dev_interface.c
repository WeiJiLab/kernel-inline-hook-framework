#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/devicestat.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <fs/devfs/devfs.h>
#include <sys/ctype.h>
#include "include/common_data.h"

static d_open_t hook_targets_open;
static d_close_t hook_targets_close;
static d_read_t hook_targets_read;
static d_write_t hook_targets_write;

MALLOC_DEFINE(M_KSYM_NAME, "ksym name buf", "ksym name buf");

static struct cdevsw c_hook_targets_cdevsw = {
	.d_version = D_VERSION,
	.d_open = hook_targets_open,
	.d_close = hook_targets_close,
	.d_read = hook_targets_read,
	.d_write = hook_targets_write,
	.d_name = "hook_targets",
};

static struct cdev *c_hook_targets = NULL;

static void
free_priv(void *arg)
{
        char *buf = arg;
        free(buf, M_KSYM_NAME);
}

static int
hook_targets_open(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	char *buf = malloc(KSYM_NAME_LEN, M_KSYM_NAME, M_ZERO | M_WAITOK);
	if (!buf)
		return ENOMEM;
	devfs_set_cdevpriv(buf, free_priv);
	return 0;
}

static int
hook_targets_close(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	return 0;
}

static int
hook_targets_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	char *buf = NULL;
	int err = devfs_get_cdevpriv((void **)&buf);
	if (err)
		return err;
	return show_all_hook_targets(buf, uio);
}

static char *
skip_spaces(char *str)
{
	while (isspace(*str))
		++str;
	return (char *)str;
}

static char *
strim(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	return skip_spaces(s);
}

static int
hook_targets_write(struct cdev *dev, struct uio *uio, int ioflag)
{   
	char *buf = NULL;
	char *string_start, *sep, *val_start;
	long val;
	void *target;
	int ret;

	int err = devfs_get_cdevpriv((void **)&buf);
	if (err)
		return err;
	memset(buf, 0, KSYM_NAME_LEN);
	err = uiomove(buf, KSYM_NAME_LEN, uio);
	if (err)
		return err; 

	string_start = strim(buf);
	if (!(sep = strchr(string_start, ' ')) || 
	    sep - buf > KSYM_NAME_LEN) {
		return EFAULT;
	}
	*sep++ = '\0';
	val_start = strim(sep);
	val = strtol(val_start, NULL, 10);

	if (!(target = find_func(string_start))) {
		return EFAULT;
	}

	switch (val) {
	case 0:
		ret = hijack_target_disable(target, false);
		break;
	case 1:
		ret = hijack_target_enable(target);
		break;
	default:
		return EFAULT;
	}

	return ret ? EFAULT : 0;
}

int
init_dev_interface(void)
{
	int err;
	err = make_dev_p(MAKEDEV_WAITOK, &c_hook_targets,
			&c_hook_targets_cdevsw, 0, UID_ROOT,
			GID_WHEEL, 0600, "hook_targets");
	if (err)
		return err;
	return 0;
}

void
remove_dev_interface(void)
{
	destroy_dev(c_hook_targets);
}