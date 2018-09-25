#pragma once

#include "common.h"

#include <kernel.h>

#define SCE_KERNEL_MAX_NAME_LENGTH 256
#define SCE_KERNEL_MAX_SEGMENTS 4
#define SCE_KERNEL_NUM_FINGERPRINT 20

#define DLSYM_MANGLED_NAME 0x1

struct _SceKernelModuleSegmentInfo {
	void* baseAddr;
	uint32_t size;
	int32_t prot;
};
typedef struct _SceKernelModuleSegmentInfo SceKernelModuleSegmentInfo;

struct _SceKernelModuleInfo {
	size_t size;
	char name[SCE_KERNEL_MAX_NAME_LENGTH];
	SceKernelModuleSegmentInfo segmentInfo[SCE_KERNEL_MAX_SEGMENTS];
	uint32_t numSegments;
	uint8_t fingerprint[SCE_KERNEL_NUM_FINGERPRINT];
};
typedef struct _SceKernelModuleInfo SceKernelModuleInfo;

int sceKernelGetModuleInfo(SceKernelModule handle, SceKernelModuleInfo* info);

int sceKernelDlsymEx(SceKernelModule handle, const char* symbol, const char* lib, unsigned int flags, void** addrp);

bool ensure_dir_exists(const char* dir, SceKernelMode mode);
