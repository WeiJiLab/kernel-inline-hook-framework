#include "hijack_arm64.h"
#include "../../include/klog.h"
#include <asm/cacheflush.h>

//There MUST be 12
/*
    stp x1, x0, [sp, #-0x20]!
    ldr x0, 8
    br x0
    .addr(low)
    .addr(high)
*/
const char long_jmp_code[12]="\xe1\x03\xbe\xa9\x40\x00\x00\x58\x00\x00\x1f\xd6";

inline void fill_long_jmp(void *fill_dest, void *hijack_to_func)
{
    memcpy(fill_dest, long_jmp_code, sizeof(long_jmp_code));
    memcpy(fill_dest + sizeof(long_jmp_code), &hijack_to_func, sizeof(void *));
}

/*
* Refer to https://github.com/CAS-Atlantic/AArch64-Encoding
*/

bool check_instruction_can_hijack(uint32_t instruction)
{
    bool ret = true;

    //todo: we want to fix these instructions
    switch(instruction & 0x9f000000u) {
        case 0x10000000u:  //adr  
        case 0x90000000u:  //adrp
            ret = false;
            goto out;
    }
    switch(instruction & 0xfc000000u) {
        case 0x14000000u:  //b  
        case 0x94000000u:  //bl
            ret = false;
            goto out;
    }
    switch(instruction & 0xff000000u) {
        case 0x54000000u:  //b.c  
            ret = false;
            goto out;
    }    
    switch(instruction & 0x7e000000u) {
        case 0x34000000u:  //cbz cbnz
        case 0x36000000u:  //tbz tbnz
            ret = false;
            goto out;
    }
    switch(instruction & 0xbf000000u) {
        case 0x18000000u:  //ldr
            ret = false;
            goto out;
    }
    switch(instruction & 0x3f000000u) {
        case 0x1c000000u:  //ldrv
            ret = false;
            goto out;
    }
    switch(instruction & 0xff000000u) {
        case 0x98000000u:  //ldrsw
            ret = false;
            goto out;
    }

out:
    if (!ret) {
        logerror("instruction %x cannot be hijacked!\n", instruction);
    }
    return ret;
}

bool check_target_can_hijack(void *target)
{
    int offset = 0;
    for (; offset < HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
        if (!check_instruction_can_hijack(*(uint32_t *)(target + offset)))
            return false;
    }
    return true;
}