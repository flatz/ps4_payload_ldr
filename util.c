#include "util.h"
#include "syscalls.h"

#include <limits.h>

enum {
	SUPERCALL_NULL,
	SUPERCALL_PEEK_POKE,
	SUPERCALL_GET_MEMORY_LAYOUT,
	SUPERCALL_SET_AUTH_INFO,
	SUPERCALL_GATE,
	SUPERCALL_DLSYM,
};

int sceKernelGetModuleInfo(SceKernelModule handle, SceKernelModuleInfo* info) {
	memset(info, 0, sizeof(*info));
	{
		info->size = sizeof(*info);
	}

	return syscall(SYS_dynlib_get_info, handle, info);
}

int sceKernelDlsymEx(SceKernelModule handle, const char* symbol, const char* lib, unsigned int flags, void** addrp) {
	return syscall(SYS_supercall, SUPERCALL_DLSYM, handle, symbol, lib, flags, addrp);
}

bool ensure_dir_exists(const char* dir, SceKernelMode mode) {
	char tmp_path[PATH_MAX];
	const char* cur;
	const char* end;
	const char* p;
	size_t len;
	int ret;
	bool status = false;

	assert(dir != NULL);

	cur = dir;
	end = cur + strlen(dir);

	for (cur = dir, end = cur + strlen(dir); cur < end && *cur != '\0'; ) {
		p = strchr(cur, '/');
		if (!p) {
			p = end;
		}
		len = (size_t)(p - dir);
		if (!len) {
			break;
		}
		if (len + 1 > sizeof(tmp_path)) {
			EPRINTF("Too large path.\n");
			goto err;
		}

		strncpy(tmp_path, dir, len);
		tmp_path[len] = '\0';

		ret = sceKernelMkdir(tmp_path, SCE_KERNEL_S_IRWU);
		if (ret < 0) {
			EPRINTF("sceKernelMkdir failed: %d\n", ret);
			goto err;
		}

		cur = p + 1;

		while (*cur == '/') {
			++cur;
		}
	}

	status = true;

err:
	return status;
}
