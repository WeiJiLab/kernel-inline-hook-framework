#include "hijack_x86_64.h"
#include <linux/string.h>

/*
	push 	%rax
	movabs 	$addr, %rax
	jmp 	*%rax
	pop 	%rax
*/
const char long_jmp_code[14]="\x50\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0\x58";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy(fill_dest + 3, &hijack_to_func, sizeof(void *));
}