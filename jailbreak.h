#pragma once

#include "common.h"

#define SIZEOF_SELF_AUTH_INFO 0x88

TYPE_BEGIN(struct self_auth_info, SIZEOF_SELF_AUTH_INFO);
	TYPE_FIELD(uint64_t paid, 0x00);
	TYPE_FIELD(uint64_t caps[4], 0x08);
	TYPE_FIELD(uint64_t attrs[4], 0x28);
	TYPE_FIELD(uint8_t unk[0x40], 0x48);
TYPE_END();

void give_me_power(bool need_root, bool need_unjail);
void give_power_back(void);
