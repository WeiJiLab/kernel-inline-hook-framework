#include "hijack_x86.h"
#include <linux/string.h>

/*
	push 	%eax
	mov 	$addr, %eax
	jmp 	*%eax
	pop 	%eax
*/
const char long_jmp_code[9]="\x50\xb8\x00\x00\x00\x00\xff\xe0\x58";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
	memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
	memcpy(fill_dest + 2, &hijack_to_func, sizeof(void *));
}