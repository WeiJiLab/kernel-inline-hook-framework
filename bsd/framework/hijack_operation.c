#include "include/common_data.h"
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/systm.h>
#include <sys/kernel.h>

LIST_HEAD(sym_hook_list, sym_hook);
static struct sym_hook_list sym_hook_list;
static struct rwlock sym_hook_list_lock;

static inline int
fill_hook_template_code_space(void *hook_template_code_space, 
    				void *target_code, void *return_addr)
{
	unsigned char tmp_code[HIJACK_SIZE * 2] = {0};
	memcpy(tmp_code, target_code, HIJACK_SIZE);
	if (fill_nop_for_code_space(tmp_code, target_code)) {
		return -1;
	}
	fill_long_jmp((char *)tmp_code + HIJACK_SIZE, return_addr);
	return hook_write_range(hook_template_code_space, tmp_code, sizeof(tmp_code));
}

struct do_hijack_struct {
	void *dest;
	void *source;
};

MALLOC_DEFINE(M_HOOK, "hookstruct", "hookstruct");

static int do_hijack_target(void *data)
{
	void *dest = ((struct do_hijack_struct *)data)->dest;
	void *source = ((struct do_hijack_struct *)data)->source;

	return hook_write_range(dest, source, HIJACK_SIZE);
}

int hijack_target_prepare(void *target, void *hook_dest, void *hook_template_code_space)
{
	struct sym_hook *sa = NULL;
	int ret = 0;

	/*first, target function should longer than HIJACK_SIZE*/
	if (!check_function_length_enough(target)) {
		printf("%p short than hijack_size %d, cannot hijack...\n",
			target, HIJACK_SIZE);
		ret = -1;
		goto out;
	}

	/*second, target cannot repeat*/
	rw_rlock(&sym_hook_list_lock);
	LIST_FOREACH(sa, &sym_hook_list, node) {
		if (target == sa->target) {
			rw_runlock(&sym_hook_list_lock);
			printf("%p has been prepared, skip...\n", target);
			ret = -1;
			goto out;
		}
	}
	rw_runlock(&sym_hook_list_lock);

	/*check passed, now to allocation*/
	sa = malloc(sizeof(*sa), M_HOOK, M_ZERO | M_WAITOK);
	if (!sa) {
		printf("No enough memory to hijack %p\n", target);
		ret = -1;
		goto out;
	}

	sa->target = target;
	memcpy(sa->target_code, target, HIJACK_SIZE);
	sa->hook_dest = hook_dest;
	sa->hook_template_code_space = hook_template_code_space;
	sa->template_return_addr = (char *)target + LONG_JMP_CODE_LEN - 1;
	sa->enabled = false;

	rw_wlock(&sym_hook_list_lock);
	LIST_INSERT_HEAD(&sym_hook_list, sa, node);
	rw_wunlock(&sym_hook_list_lock);

out:
	return ret;
}

int hijack_target_enable(void *target)
{
	struct sym_hook *sa;
	int ret = -1;
	unsigned char source_code[HIJACK_SIZE] = {0};
	struct do_hijack_struct do_hijack_struct = {
		.dest = target,
		.source = source_code,
	};

	rw_wlock(&sym_hook_list_lock);
	LIST_FOREACH(sa, &sym_hook_list, node) {
		if (sa->target == target) {
			if (sa->enabled == false) {
				if (sa->hook_template_code_space &&
				    fill_hook_template_code_space(
					sa->hook_template_code_space,
					sa->target_code, 
					sa->template_return_addr)) {
					goto out;
				}
				memcpy(source_code, sa->target_code, HIJACK_SIZE);
				fill_long_jmp(source_code, sa->hook_dest);
				if ((ret = fill_nop_for_target(source_code, sa->target)))
					goto out;
				if (!(ret = do_hijack_target(&do_hijack_struct))) {
					sa->enabled = true;
				}
			} else {
				printf("%p has been hijacked, skip...\n", sa->target);
				ret = 0;
			}
			goto out;
		}
	}
	printf("%p not been prepared, skip...\n", target);
out:
	rw_wunlock(&sym_hook_list_lock);

	return ret;
}

int hijack_target_disable(void *target, bool need_remove)
{
	struct sym_hook *sa, *tmp;
	int ret = -1;
	struct do_hijack_struct do_hijack_struct = {
		.dest = target
	};    

	rw_wlock(&sym_hook_list_lock);
	LIST_FOREACH_SAFE(sa, &sym_hook_list, node, tmp) {
		if (sa->target == target) {
			if (sa->enabled == true) {
				do_hijack_struct.source = sa->target_code;
				if (!(ret = do_hijack_target(&do_hijack_struct)))
					sa->enabled = false;
			} else {
				printf("%p has been disabled\n", sa->target);
				ret = 0;
			}

			if (need_remove && !ret) {
				printf("remove hijack target %p\n", target);
				LIST_REMOVE(sa, node);
				free(sa, M_HOOK);
			}
			goto out;
		}
	}
	printf("%p not been prepared, skip...\n", target);
out:
	rw_wunlock(&sym_hook_list_lock);

	return ret;
}

void hijack_target_disable_all(bool need_remove)
{
	struct sym_hook *sa, *tmp;
	bool retry;
	struct do_hijack_struct do_hijack_struct;

	do {
		retry = false;
		rw_wlock(&sym_hook_list_lock);
		LIST_FOREACH_SAFE(sa, &sym_hook_list, node, tmp) {
			if (sa->enabled == true) {
				do_hijack_struct.dest = sa->target;
				do_hijack_struct.source = sa->target_code;
				if (do_hijack_target(&do_hijack_struct)) {
					retry = true;
					continue;
				}
				sa->enabled = false;
			}
			if (need_remove) {
				LIST_REMOVE(sa, node);
				free(sa, M_HOOK);
			}
		}
		rw_wunlock(&sym_hook_list_lock);
	} while(retry && (DELAY(1000000), true));

	printf("all hijacked target disabled%s\n", need_remove ?" and removed":"");
	return;
}

/************************************************************************************/

int init_hijack_operation(void)
{
	LIST_INIT(&sym_hook_list);
	rw_init(&sym_hook_list_lock, "hook list lock");
	return 0;
}