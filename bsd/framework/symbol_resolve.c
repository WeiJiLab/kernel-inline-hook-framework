#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/link_elf.h>
#include "include/common_data.h"

struct sym_elem {
	const char *name;
	caddr_t val;
};

static int search_symbol_name(linker_file_t lf, void *arg)
{
	struct sym_elem *se = (struct sym_elem *)arg;

	se->val = linker_file_lookup_symbol(lf, se->name, 0);
	return se->val > 0;
}

char *find_func(const char *name)
{
	int ret;
	struct sym_elem se = {
		.val = 0, 
		.name = name,
	};
	
	ret = linker_file_foreach(search_symbol_name, &se);
	
	if (!ret) {
		printf("Symbol %s not found!\n", name);
	}
	return (char *)se.val;
}

bool check_function_length_enough(void *target)
{
	char namebuf_orig[64] = {0};
	char namebuf_aft[64] = {0};
	long offset = 0;
	int ret = 0;

	ret = linker_ddb_search_symbol_name((caddr_t)target,
						namebuf_orig, 64, &offset);
	if (ret)
		goto fail;
	ret = linker_ddb_search_symbol_name((caddr_t)target + HIJACK_SIZE,
						namebuf_aft, 64, &offset);
	if (ret)
		goto fail;
	if (strcmp(namebuf_orig, namebuf_aft))
		goto fail;
	return true;
fail:
	return false;
}