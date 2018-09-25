#include "network.h"

#define NET_HEAP_SIZE (1 * 1024 * 1024)

static int s_libnet_mem_id = -1;

static bool s_network_initialized = false;

bool network_init(void) {
	int ret;

	if (s_network_initialized) {
		goto done;
	}

	ret = sceNetInit();
	if (ret < 0) {
		EPRINTF("sceNetInit failed: %d\n", sce_net_errno);
		goto err;
	}

	ret = sceNetPoolCreate("payload_ldr", NET_HEAP_SIZE, 0);
	if (ret < 0) {
		EPRINTF("sceNetPoolCreate failed: %d\n", sce_net_errno);
		goto err_net_term;
	}
	s_libnet_mem_id = ret;

	s_network_initialized = true;

done:
	return true;

err_pool_destroy:
	if (s_libnet_mem_id >= 0) {
		ret = sceNetPoolDestroy(s_libnet_mem_id);
		if (ret < 0) {
			EPRINTF("sceNetPoolDestroy failed: %d\n", sce_net_errno);
		}

		s_libnet_mem_id = -1;
	}

err_net_term:
	ret = sceNetTerm();
	if (ret < 0) {
		EPRINTF("sceNetTerm failed: %d\n", sce_net_errno);
	}

err:
	return false;
}

void network_fini(void) {
	int ret;

	if (!s_network_initialized) {
		return;
	}

	if (s_libnet_mem_id >= 0) {
		ret = sceNetPoolDestroy(s_libnet_mem_id);
		if (ret < 0) {
			EPRINTF("sceNetPoolDestroy failed: %d\n", sce_net_errno);
		}

		s_libnet_mem_id = -1;
	}

	ret = sceNetTerm();
	if (ret < 0) {
		EPRINTF("sceNetTerm failed: %d\n", sce_net_errno);
	}

	s_network_initialized = false;
}

int send_all(SceNetId sock_id, const void* data, size_t size, size_t* sent) {
	size_t total_sent= 0;
	size_t cur_size;
	uint8_t* ptr = (uint8_t*)data;
	int ret;

	while (total_sent < size) {
		cur_size = size - total_sent;

		ret = sceNetSend(sock_id, ptr, cur_size, 0);
		if (ret < 0) {
			EPRINTF("sceNetSend failed: %d\n", sce_net_errno);
			goto err;
		}
		if (ret == 0) {
			break;
		}

		total_sent += ret;
		ptr += ret;
	}

	ret = 0;

err:
	if (sent)
		*sent = total_sent;

	return ret;
}

int recv_all(SceNetId sock_id, void* data, size_t size, size_t* received) {
	size_t total_received = 0;
	size_t cur_size;
	uint8_t* ptr = (uint8_t*)data;
	int ret;

	while (total_received < size) {
		cur_size = size - total_received;

		ret = sceNetRecv(sock_id, ptr, cur_size, 0);
		if (ret < 0) {
			EPRINTF("sceNetRecv failed: %d\n", sce_net_errno);
			goto err;
		}
		if (ret == 0) {
			break;
		}

		total_received += ret;
		ptr += ret;
	}

	ret = 0;

err:
	if (received)
		*received = total_received;

	return ret;
}
