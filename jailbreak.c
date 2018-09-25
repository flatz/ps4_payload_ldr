#include "jailbreak.h"
#include "syscalls.h"

#define ACMGR_CAPABILITY_SYSTEM (UINT64_C(1) << 62)

#define GAIN_PRIVILEGE_ROOT   (1 << 0)
#define GAIN_PRIVILEGE_UNJAIL (1 << 1)

static struct self_auth_info s_old_auth_info;
static bool s_need_system_cap = false;

typedef void (*gain_privileges_cb_t)(struct self_auth_info* auth_info);

static int sys_gain_privileges(unsigned int flags, gain_privileges_cb_t cb) {
	return syscall(SYS_gain_privileges, flags, cb);
}

static void gain_privileges_cb(struct self_auth_info* info) {
	memcpy(&s_old_auth_info, info, sizeof(*info));

	if (s_need_system_cap) {
		info->caps[0] |= ACMGR_CAPABILITY_SYSTEM;
	}
}

static void ungain_privileges_cb(struct self_auth_info* info) {
	memcpy(info, &s_old_auth_info, sizeof(*info));
}

void give_me_power(bool need_root, bool need_unjail) {
	unsigned int flags = 0;

	if (need_root) {
		flags |= GAIN_PRIVILEGE_ROOT;
		s_need_system_cap = true;
	}
	if (need_unjail) {
		flags |= GAIN_PRIVILEGE_UNJAIL;
	}

	sys_gain_privileges(flags, &gain_privileges_cb);
}

void give_power_back(void) {
	sys_gain_privileges(0, &ungain_privileges_cb);
}
