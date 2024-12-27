#ifndef _COMMON_DATA_H_
#define _COMMON_DATA_H_

#ifdef _amd64_
#include "hijack_amd64.h"
#endif
#ifdef _arm64_
#include "hijack_arm64.h"
#endif
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#define DEFAULT_HASH_BUCKET_BITS   17
#define KSYM_NAME_LEN 64

struct sym_hook {
	void *target;
	void *hook_dest;
	void *template_return_addr;
	void *hook_template_code_space;
	bool enabled;
	LIST_ENTRY(sym_hook) node;
	unsigned char target_code[HIJACK_SIZE];
};

char *find_func(const char *name);
bool check_function_length_enough(void *target);
bool check_target_can_hijack(void *target);
int hook_write_range(void *target, void *source, int size);
void fill_long_jmp(void *fill_dest, void *hijack_to_func);
int init_dev_interface(void);
void remove_dev_interface(void);

bool hook_sys_openat_init(void);
void hook_sys_openat_exit(void);
bool hook__fdrop_init(void);
void hook__fdrop_exit(void);

int hijack_target_prepare(void *target, void *hook_dest, void *hook_template_code_space);
int hijack_target_enable(void *target);
int hijack_target_disable(void *target, bool need_remove);
void hijack_target_disable_all(bool need_remove);
int show_all_hook_targets(char *buf, struct uio *uio);
int init_hijack_operation(void);

#define SHOW_KSYM_CACHE 1
#define CLEAN_ALL_KSYM_CACHE (1 << 1)
#endif