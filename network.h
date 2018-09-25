#pragma once

#include "common.h"

#include <net.h>

bool network_init(void);
void network_fini(void);

int send_all(SceNetId sock_id, const void* data, size_t size, size_t* sent);
int recv_all(SceNetId sock_id, void* data, size_t size, size_t* received);
