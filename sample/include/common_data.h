#ifndef _COMMON_DATA_H_
#define _COMMON_DATA_H_

#ifdef _ARCH_ARM64_
#include "hijack_arm64.h"
#endif

#ifdef _ARCH_ARM_
#include "hijack_arm.h"
#endif

#ifdef _ARCH_X86_64_
#include "hijack_x86_64.h"
#endif

#ifdef _ARCH_X86_
#include "hijack_x86.h"
#endif

#ifdef _ARCH_POWERPC_
#include "hijack_powerpc.h"
#endif

#endif