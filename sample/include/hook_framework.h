#ifndef _HOOK_FRAMEWORK_H_
#define _HOOK_FRAMEWORK_H_

#include <linux/types.h>

extern int hijack_target_prepare(void *target, void *hook_dest, void *hook_template_code_space);
extern int hijack_target_enable(void *target);
extern int hijack_target_disable(void *target, bool need_remove);
extern void hijack_target_disable_all(bool need_remove);
extern void *find_func(const char *name);

#endif