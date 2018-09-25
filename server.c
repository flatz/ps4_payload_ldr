#include "server.h"
#include "network.h"
#include "elf.h"
#include "jailbreak.h"
#include "util.h"

#include <limits.h>
#include <kernel.h>
#include <system_service.h>

#define MAX_SOCKETS (5)
#define MAX_EVENTS (16)

#define MAX_FILE_SIZE (256 * 1024 * 1024)
#define MAX_ELF_PHDRS (16)
#define MAX_ELF_SHDRS (32)

#define BACKLOG (5)
#define SOCKET_BUF_SIZE (1460)
#define POLL_TIMEOUT (15 * 1000 * 1000)

#define F_SERVER_LISTENING_SOCKET (0x00000001)

#define SPAWNED_SELF_DIR "/data/self"

#define ACK UINT32_C(0xABADC0FE)

#ifndef SCE_KERNEL_MAP_ANON
#	define SCE_KERNEL_MAP_ANON MAP_ANON
#endif

enum {
	EVENT_CODE_AGAIN,
	EVENT_CODE_TERM,
};

enum {
	FLAG_DONT_STOP   = (1 << 0),
	FLAG_USE_SPAWN   = (1 << 1),
	FLAG_NEED_ROOT   = (1 << 2),
	FLAG_NEED_UNJAIL = (1 << 3),
};

struct elf_info;

typedef int elf_entry(const struct elf_info* info);

struct elf_info {
	uint64_t map_base, map_size;
	uint64_t rx_base, rw_base;
	uint64_t rx_size, rw_size;
	elf_entry* entry;
};

static SceNetId s_epoll_id = -1;
static SceNetId s_server_sock_id = -1;
static SceNetSockaddrIn s_server_addr;
static SceNetId s_sockets[MAX_SOCKETS];

static bool s_server_initialized = false;

static int handle_server_socket(SceNetEpollEvent* evt);
static int handle_client_socket(SceNetEpollEvent* evt);
static int handle_client_socket_internal(SceNetId sock_id);

static bool add_socket(SceNetId sock_id, SceNetEpollEvent* evt);
static bool remove_socket(SceNetId sock_id);
static bool close_socket(SceNetId sock_id);

static bool process_elf(const uint8_t* file_data, uint64_t file_size, struct elf_info* info);
static inline bool is_elf_good(struct elf64_ehdr* ehdr);

static void undo_privileges(void);

bool server_start(int port) {
	SceNetEpollEvent evt;
	int opt_val;
	size_t i;
	int ret;

	assert(port < 0);

	if (port < 0) {
		EPRINTF("Bad port specified: %d\n", port);
		ret = -EINVAL;
		goto err;
	}

	memset(s_sockets, 0, sizeof(s_sockets));
	{
		for (i = 0; i < ARRAY_SIZE(s_sockets); ++i) {
			s_sockets[i] = -1;
		}
	}

	ret = sceNetEpollCreate("payload_ldr", 0);
	if (ret < 0) {
		EPRINTF("sceNetEpollCreate failed: %d\n", sce_net_errno);
		goto err;
	}
	s_epoll_id = ret;

	ret = sceNetSocket("payload_ldr", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
	if (ret < 0) {
		EPRINTF("sceNetEpollCreate failed: %d\n", sce_net_errno);
		goto err_epoll_destroy;
	}
	s_server_sock_id = ret;

	opt_val = 1;
	ret = sceNetSetsockopt(s_server_sock_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt_val, sizeof(opt_val));
	if (ret < 0) {
		EPRINTF("sceNetSetsockopt failed: %d\n", sce_net_errno);
		goto err_socket_close;
	}

	memset(&s_server_addr, 0, sizeof(s_server_addr));
	{
		s_server_addr.sin_len = sizeof(s_server_addr);
		s_server_addr.sin_family = SCE_NET_AF_INET;
		s_server_addr.sin_port = sceNetHtons((SceNetInPort_t)port);
	}

	ret = sceNetBind(s_server_sock_id, (SceNetSockaddr*)&s_server_addr, sizeof(s_server_addr));
	if (ret < 0) {
		EPRINTF("sceNetBind failed: %d\n", sce_net_errno);
		goto err_socket_close;
	}

	ret = sceNetListen(s_server_sock_id, BACKLOG);
	if (ret < 0) {
		EPRINTF("sceNetBind failed: %d\n", sce_net_errno);
		goto err_socket_close;
	}

#if defined(SOCKET_BUF_SIZE)
	opt_val = SOCKET_BUF_SIZE;
	ret = sceNetSetsockopt(s_server_sock_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVBUF, &opt_val, sizeof(opt_val));
	if (ret < 0) {
		EPRINTF("sceNetSetsockopt failed: %d\n", sce_net_errno);
		goto err_socket_close;
	}
#endif

	memset(&evt, 0, sizeof(evt));
	{
		evt.events = SCE_NET_EPOLLIN;
		evt.data.u32 = F_SERVER_LISTENING_SOCKET;
	}
	if (!add_socket(s_server_sock_id, &evt)) {
		goto err_socket_close;
	}

	s_server_initialized = true;

	return true;

err_socket_close:
	if (s_server_sock_id >= 0) {
		close_socket(s_server_sock_id);
		s_server_sock_id = -1;
	}

err_epoll_destroy:
	if (s_epoll_id >= 0) {
		ret = sceNetEpollDestroy(s_epoll_id);
		if (ret < 0) {
			EPRINTF("sceNetEpollDestroy failed: %d\n", sce_net_errno);
		}

		s_epoll_id = -1;
	}

err:
	memset(s_sockets, 0, sizeof(s_sockets));

	return false;
}

bool server_listen(void) {
	SceNetEpollEvent evts[MAX_EVENTS];
	int nevents;
	int i;
	int ret;

	if (!s_server_initialized) {
		goto err;
	}

	for (;;) {
		ret = sceNetEpollWait(s_epoll_id, evts, ARRAY_SIZE(evts), POLL_TIMEOUT);
		if (ret < 0) {
			EPRINTF("sceNetEpollWait failed: %d\n", sce_net_errno);
			goto err;
		}
		nevents = ret;

		if (nevents == 0) {
#if 0
			sceNetShowNetstat();
#endif
			continue;
		}

		for (i = 0; i < nevents; ++i) {
			if (evts[i].data.u32 & F_SERVER_LISTENING_SOCKET) {
				ret = handle_server_socket(&evts[i]);
				if (ret == EVENT_CODE_TERM) {
					goto done;
				}
			} else {
				ret = handle_client_socket(&evts[i]);
				if (ret == EVENT_CODE_TERM) {
					goto done;
				}
			}
		}
	}

done:
	return true;

err:
	return false;
}

void server_stop(void) {
	size_t i;
	int ret;

	if (!s_server_initialized) {
		return;
	}

	for (i = 0; i < ARRAY_SIZE(s_sockets); ++i) {
		if (s_sockets[i] < 0) {
			continue;
		}

		remove_socket(s_sockets[i]);
	}
	memset(s_sockets, 0, sizeof(s_sockets));

	if (s_server_sock_id >= 0) {
		close_socket(s_server_sock_id);
		s_server_sock_id = -1;
	}

	if (s_epoll_id >= 0) {
		ret = sceNetEpollDestroy(s_epoll_id);
		if (ret < 0) {
			EPRINTF("sceNetEpollDestroy failed: %d\n", sce_net_errno);
		}

		s_epoll_id = -1;
	}

	s_server_initialized = false;
}

static int handle_server_socket(SceNetEpollEvent* evt) {
	SceNetId sock_id, new_sock_id;
	SceNetSockaddrIn sock_addr;
	SceNetSocklen_t sock_addr_len;
	SceNetEpollEvent new_evt;
	char addr_str[SCE_NET_INET_ADDRSTRLEN];
	int port;
	int ret;

	assert(evt != NULL);

	sock_id = (SceNetId)evt->ident;

	if (evt->events & SCE_NET_EPOLLHUP) {
		return EVENT_CODE_TERM;
	}

	if (evt->events & SCE_NET_EPOLLERR) {
		return EVENT_CODE_TERM;
	}

	if (evt->events & SCE_NET_EPOLLIN) {
		sock_addr_len = sizeof(sock_addr);
		ret = sceNetAccept(sock_id, (SceNetSockaddr*)&sock_addr, &sock_addr_len);
		if (ret < 0) {
			EPRINTF("sceNetAccept failed: %d\n", sce_net_errno);
			return EVENT_CODE_TERM;
		}
		new_sock_id = ret;

		if (sceNetInetNtop(SCE_NET_AF_INET, &sock_addr.sin_addr, addr_str, sizeof(addr_str)) == NULL) {
			strlcpy(addr_str, "?", sizeof(addr_str));
		}
		port = sceNetNtohs(sock_addr.sin_port);
		printf("Connected from %s:%d\n", addr_str, port);

		memset(&new_evt, 0, sizeof(new_evt));
		{
			new_evt.events = SCE_NET_EPOLLIN;
			new_evt.data.u32 = 0;
		}
		if (!add_socket(new_sock_id, &new_evt)) {
			close_socket(new_sock_id);
		}

		return EVENT_CODE_AGAIN;
	}

	printf("No events occured.\n");

	return EVENT_CODE_AGAIN;
}

static int handle_client_socket(SceNetEpollEvent* evt) {
	SceNetId sock_id;
	SceNetSocklen_t opt_len;
	int err;
	int ret;

	assert(evt != NULL);

	sock_id = (SceNetId)evt->ident;

	if (evt->events & SCE_NET_EPOLLHUP) {
		remove_socket(sock_id);
		return EVENT_CODE_AGAIN;
	}

	if (evt->events & SCE_NET_EPOLLERR) {
		err = 0;
		opt_len = sizeof(err);
		ret = sceNetGetsockopt(sock_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_ERROR, &err, &opt_len);
		if (ret < 0) {
			EPRINTF("sceNetGetsockopt failed: %d\n", sce_net_errno);
		}
		if (err != 0) {
			printf("SCE_NET_EPOLLERR: %d\n", err);
		}

		remove_socket(sock_id);

		return EVENT_CODE_AGAIN;
	}

	if (evt->events & SCE_NET_EPOLLIN) {
		ret = handle_client_socket_internal(sock_id);

		remove_socket(sock_id);

		return ret;
	}

	return EVENT_CODE_AGAIN;
}

static int handle_client_socket_internal(SceNetId sock_id) {
	char self_file_path[PATH_MAX];
	struct elf_info info;
	uint8_t* file_data = NULL;
	uint8_t* extra_data = NULL;
	char** args = NULL;
	size_t nargs = 0;
	char* arg_cur;
	char* arg_end;
	struct iovec* iov = NULL;
	int iovlen = 0;
	struct {
		char file_path[256];
		uint64_t file_size;
		uint32_t extra_size;
		uint32_t flags;
	} hdr;
	int fd = -1;
	size_t n;
	uint32_t ack;
	ssize_t nwritten;
	bool status = false;
	int result = EVENT_CODE_AGAIN;
	int ret;

	printf("Handling client request...\n");

	//printf("Receiving header...\n");
	ret = recv_all(sock_id, &hdr, sizeof(hdr), &n);
	if (ret < 0) {
		goto err;
	}
	if (n != sizeof(hdr)) {
		EPRINTF("Insufficient data received (expected: 0x%" PRIXMAX ", got: 0x%" PRIXMAX ").\n", (uintmax_t)sizeof(hdr), (uintmax_t)n);
		goto err;
	}

	hdr.file_path[sizeof(hdr.file_path) - 1] = '\0';
	if (hdr.flags & FLAG_USE_SPAWN) {
		n = strlen(hdr.file_path);
		if (n == 0) {
			EPRINTF("Empty file path.\n");
			goto err;
		}
		if (hdr.file_path[0] == '/' || hdr.file_path[0] == '.') {
			EPRINTF("Bad file path: %s\n", hdr.file_path);
			goto err;
		}
	}

	if (hdr.file_size > 0) {
		//printf("File size: 0x%" PRIX64 "\n", hdr.file_size);
		if (hdr.file_size > MAX_FILE_SIZE) {
			EPRINTF("Too large file size.\n");
			goto err;
		}

		//printf("Allocating memory for elf file of size 0x%" PRIX64 "...\n", hdr.file_size);
		file_data = (uint8_t*)malloc(hdr.file_size);
		if (!file_data) {
			EPRINTF("No memory for file data.\n");
			goto err;
		}
		memset(file_data, 0, hdr.file_size);

		//printf("Receiving elf file data...\n");
		ret = recv_all(sock_id, file_data, hdr.file_size, &n);
		if (ret < 0) {
			goto err;
		}
		if (n != hdr.file_size) {
			EPRINTF("Insufficient data received (expected: 0x%" PRIX64 ", got: 0x%" PRIXMAX ").\n", hdr.file_size, (uintmax_t)n);
			goto err;
		}
	}

	if (hdr.extra_size > 0) {
		//printf("Allocating memory for extra data of size 0x%" PRIX32 "...\n", hdr.extra_size + 1);
		extra_data = (uint8_t*)malloc(hdr.extra_size + 1);
		if (!extra_data) {
			EPRINTF("No memory for extra data.\n");
			goto err;
		}
		memset(extra_data, 0, hdr.extra_size + 1);

		//printf("Receiving extra data...\n");
		ret = recv_all(sock_id, extra_data, hdr.extra_size, &n);
		if (ret < 0) {
			goto err;
		}
		if (n != hdr.extra_size) {
			EPRINTF("Insufficient data received (expected: 0x%" PRIX32 ", got: 0x%" PRIXMAX ").\n", hdr.extra_size, (uintmax_t)n);
			goto err;
		}
	}

	if (hdr.flags & FLAG_USE_SPAWN) {
		if (!ensure_dir_exists(SPAWNED_SELF_DIR, SCE_KERNEL_S_IRWU)) {
			EPRINTF("Cannot create directory for self file.");
			goto err;
		}

		n = strlcpy(self_file_path, SPAWNED_SELF_DIR "/", sizeof(self_file_path));
		if (n >= sizeof(self_file_path)) {
too_long_file_path:
			EPRINTF("Too long file path.");
			goto err;
		}
		n = strlcat(self_file_path, hdr.file_path, sizeof(self_file_path));
		if (n >= sizeof(self_file_path)) {
			goto too_long_file_path;
		}

		if (file_data) {
			//printf("Creating self file...\n");
			ret = sceKernelOpen(self_file_path, SCE_KERNEL_O_WRONLY | SCE_KERNEL_O_CREAT | SCE_KERNEL_O_TRUNC, SCE_KERNEL_S_IRUSR | SCE_KERNEL_S_IWUSR | SCE_KERNEL_S_IXUSR);
			if (ret < 0) {
				EPRINTF("sceKernelOpen failed: %d\n", ret);
				goto err;
			}
			fd = ret;

			//printf("Writing data to self file...\n");
			nwritten = sceKernelWrite(fd, file_data, hdr.file_size);
			if (nwritten < 0) {
				EPRINTF("sceKernelWrite failed: %d\n", (int)nwritten);
				goto err;
			}
			if (nwritten != hdr.file_size) {
				EPRINTF("Insufficient data written (expected: 0x%" PRIX64 ", got: 0x%" PRIXMAX ").\n", hdr.file_size, (uintmax_t)nwritten);
				goto err;
			}

			//printf("Closing self file...\n");
			sceKernelClose(fd);
			fd = -1;

			//printf("Syncing...\n");
			sceKernelSync();
		}
	} else {
		if (file_data) {
			//printf("Processing elf file...\n");
			memset(&info, 0, sizeof(info));
			if (!process_elf(file_data, hdr.file_size, &info)) {
				EPRINTF("Bad elf file.\n");
				goto err;
			}
		} else {
			EPRINTF("No file data.\n");
			goto err;
		}
	}

	if (file_data) {
		//printf("Freeing memory of elf file...\n");
		free(file_data);
		file_data = NULL;
	}

	//printf("Sending acknowledge...\n");
	ack = ACK;
	ret = send_all(sock_id, &ack, sizeof(ack), &n);
	if (ret < 0) {
		goto err;
	}
	if (n != sizeof(ack)) {
		EPRINTF("Insufficient data sent (expected: 0x%" PRIXMAX ", sent: 0x%" PRIXMAX ").\n", (uintmax_t)sizeof(ack), n);
		goto err;
	}

	if (hdr.flags & (FLAG_NEED_ROOT | FLAG_NEED_UNJAIL)) {
		//printf("Gaining privileges...\n");
		give_me_power((hdr.flags & FLAG_NEED_ROOT) != 0, (hdr.flags & FLAG_NEED_UNJAIL) != 0);
		//atexit(&undo_privileges);
	}

	if (hdr.flags & FLAG_USE_SPAWN) {
		if (hdr.extra_size > 0) {
			arg_end = (char*)extra_data + hdr.extra_size;

			//printf("Parsing arguments list...\n");
			arg_cur = (char*)extra_data;
			for (nargs = 0; arg_cur < arg_end; ++nargs) {
				arg_cur += strlen(arg_cur) + 1;
			}
			//printf("Number of arguments: %" PRIXMAX "\n", (uintmax_t)nargs);

			//printf("Allocating memory for arguments of size 0x%" PRIXMAX "...\n", sizeof(*args) * (nargs + 1));
			args = (char**)malloc(sizeof(*args) * (nargs + 1));
			if (!args) {
				EPRINTF("No memory for arguments.\n");
				goto err;
			}
			memset(args, 0, sizeof(*args) * (nargs + 1));

			arg_cur = (char*)extra_data;
			for (n = 0; arg_cur < arg_end && n < nargs; ++n) {
				args[n] = arg_cur;
				//printf("Argument %02" PRIXMAX ": %s\n", (uintmax_t)n, args[n]);
				arg_cur += strlen(arg_cur) + 1;
			}
		}

		//printf("Hiding splash screen...\n");
		ret = sceSystemServiceHideSplashScreen();
		if (ret) {
			EPRINTF("sceSystemServiceHideSplashScreen failed: %d\n", ret);
		}

		printf("Launching self file: %s\n", self_file_path);
		ret = sceSystemServiceLoadExec(self_file_path, args);
		if (ret) {
			EPRINTF("sceSystemServiceLoadExec failed: %d\n", ret);
			goto err;
		}
	} else {
		//printf("Hiding splash screen...\n");
		ret = sceSystemServiceHideSplashScreen();
		if (ret) {
			EPRINTF("sceSystemServiceHideSplashScreen failed: %d\n", ret);
		}

		printf("Launching payload at 0x%" PRIX64 "...\n", (uint64_t)info.entry);
		ret = (*info.entry)(&info);
		if (ret) {
			printf("Exit code: %d\n", ret);
		}
	}

	result = (hdr.flags & FLAG_DONT_STOP) ? EVENT_CODE_AGAIN : EVENT_CODE_TERM;

err:
	if (fd >= 0) {
		//printf("Closing self file...\n");
		sceKernelClose(fd);
	}

	if (args) {
		//printf("Freeing arguments list...\n");
		free(args);
	}

	if (extra_data) {
		//printf("Freeing memory of extra data...\n");
		free(extra_data);
	}

	if (file_data) {
		//printf("Freeing memory of elf file...\n");
		free(file_data);
	}

	if (iov) {
		free(iov);
	}

	return result;
}

static bool add_socket(SceNetId sock_id, SceNetEpollEvent* evt) {
	size_t i;
	int ret;

	assert(sock_id >= 0);
	assert(evt != NULL);

	for (i = 0; i < ARRAY_SIZE(s_sockets); ++i) {
		if (s_sockets[i] < 0) {
			s_sockets[i] = sock_id;
			break;
		}
	}
	if (i == ARRAY_SIZE(s_sockets)) {
		EPRINTF("Client limit reached.\n");
		goto err;
	}

	ret = sceNetEpollControl(s_epoll_id, SCE_NET_EPOLL_CTL_ADD, sock_id, evt);
	if (ret < 0) {
		EPRINTF("sceNetEpollControl failed: %d\n", sce_net_errno);
		goto err;
	}

	return true;

err:
	return false;
}

static bool remove_socket(SceNetId sock_id) {
	size_t i;
	int ret;

	assert(sock_id >= 0);

	for (i = 0; i < ARRAY_SIZE(s_sockets); ++i) {
		if (s_sockets[i] == sock_id) {
			s_sockets[i] = -1;
			break;
		}
	}
	if (i == ARRAY_SIZE(s_sockets)) {
		EPRINTF("No such socket: %d\n", (int)sock_id);
		goto err;
	}

	ret = sceNetEpollControl(s_epoll_id, SCE_NET_EPOLL_CTL_DEL, sock_id, NULL);
	if (ret < 0) {
		EPRINTF("sceNetEpollControl failed: %d\n", sce_net_errno);
		goto err;
	}

 	if (sock_id != s_server_sock_id) {
		close_socket(sock_id);
	}

	return true;

err:
	return false;
}

static bool close_socket(SceNetId sock_id) {
	int ret;
	bool status = true;

	assert(sock_id >= 0);

	if (sock_id < 0) {
		return false;
	}

	ret = sceNetShutdown(sock_id, SCE_NET_SHUT_RDWR);
	if (ret < 0) {
		EPRINTF("sceNetShutdown failed: %d\n", sce_net_errno);
		status = false;
	}

	ret = sceNetSocketClose(sock_id);
	if (ret < 0) {
		EPRINTF("sceNetSocketClose failed: %d\n", sce_net_errno);
		status = false;
	}

	return status;
}

static bool process_elf(const uint8_t* file_data, uint64_t file_size, struct elf_info* info) {
	struct elf64_ehdr* ehdr;
	struct elf64_phdr* phdrs;
	struct elf64_shdr* shdrs;
	struct elf64_phdr* phdr;
	struct elf64_shdr* shdr;
	uint64_t map_base_min, map_base_max;
	uint64_t map_size = 0;
	uint64_t rx_base, rx_offset, rx_memsz, rx_filesz;
	uint64_t rw_base, rw_offset, rw_memsz, rw_filesz;
	uint64_t entry;
	uint64_t va, sz;
	uint8_t* base = NULL;
	size_t i;
	bool status = false;
	int ret;

	assert(file_data != NULL);
	assert(info != NULL);

	printf("Parsing elf header...\n");
	ehdr = (struct elf64_ehdr*)file_data;
	if (!is_elf_good(ehdr)) {
		EPRINTF("Bad elf format.\n");
		goto err;
	}

	phdrs = (struct elf64_phdr*)(file_data + LE64(ehdr->phoff));
	if (LE16(ehdr->phnum) > 0) {
		printf("Parsing elf program headers...\n");

		map_base_min = UINT64_MAX;
		map_base_max = 0;

		rx_base = rw_base = UINT64_MAX;
		rx_offset = rw_offset = 0;
		rx_memsz = rw_memsz = 0;
		rx_filesz = rw_filesz = 0;

		for (i = 0; i < LE32(ehdr->phnum); ++i) {
			phdr = phdrs + i;

			if (LE32(phdr->type) != ELF_PHDR_TYPE_LOAD) {
				continue;
			}

			va = LE64(phdr->vaddr);
			va = ALIGN_DOWN(va, SCE_KERNEL_PAGE_SIZE);

			sz = LE64(phdr->memsz);
			sz = ALIGN_UP(sz, SCE_KERNEL_PAGE_SIZE);

			map_base_min = MIN(map_base_min, va);
			map_base_max = MAX(map_base_max, va + sz);

			switch (phdr->flags) {
				case (ELF_PHDR_FLAG_R | ELF_PHDR_FLAG_X):
					rx_base = LE64(phdr->vaddr);
					rx_offset = LE64(phdr->offset);
					rx_memsz = sz;
					rx_filesz = LE64(phdr->filesz);
				break;

				case (ELF_PHDR_FLAG_R | ELF_PHDR_FLAG_W):
					rw_base = LE64(phdr->vaddr);
					rw_offset = LE64(phdr->offset);
					rw_memsz = sz;
					rw_filesz = LE64(phdr->filesz);
				break;
			}
		}
		if (map_base_min == UINT64_MAX || map_base_max == 0) {
bad_layout:
			EPRINTF("Bad memory layout.\n");
			goto err;
		}

		map_size = ALIGN_UP(map_base_max - map_base_min, SCE_KERNEL_PAGE_SIZE);
		if (map_size == 0) {
			goto bad_layout;
		}

		rx_base -= map_base_min;
		rw_base -= map_base_min;

		printf("Mapping program memory space of size 0x%" PRIX64 "...\n", map_size);
		ret = sceKernelMmap(NULL, map_size, SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_WRITE | SCE_KERNEL_PROT_CPU_EXEC, SCE_KERNEL_MAP_SHARED | SCE_KERNEL_MAP_ANON, -1, 0, (void**)&base);
		if (ret < 0) {
			EPRINTF("sceKernelMmap failed: %d\n", ret);
			goto err;
		}
		memset(base, 0, map_size);

		info->map_base = (uint64_t)base;
		info->map_size = map_size;

		printf("Map base: 0x%" PRIX64 "\n", info->map_base);
		printf("Map size: 0x%" PRIX64 "\n", info->map_size);

		if (rx_base != UINT64_MAX && rx_memsz > 0) {
			printf("Processing RX memory segment (addr: 0x%" PRIX64 ", mem size: 0x%" PRIX64 ", file size: 0x%" PRIX64 ")...\n", (uint64_t)base + rx_base, rx_memsz, rx_filesz);

			if (rx_filesz > 0) {
				printf("Copying segment data...\n");
				memcpy(base + rx_base, file_data + rx_offset, rx_filesz);
			}

			printf("Changing memory segment protection...\n");
			ret = sceKernelMprotect(base + rx_base, rx_memsz, SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC);
			if (ret < 0) {
				EPRINTF("sceKernelMprotect(rx) failed: %d\n", ret);
				goto err;
			}

			info->rx_base = (uint64_t)(base + rx_base);
			info->rx_size = rx_memsz;
		}

		if (rw_base != UINT64_MAX && rw_memsz > 0) {
			printf("Processing RW memory segment (addr: 0x%" PRIX64 ", mem size: 0x%" PRIX64 ", file size: 0x%" PRIX64 ")...\n", (uint64_t)base + rw_base, rw_memsz, rw_filesz);

			if (rw_filesz > 0) {
				printf("Copying segment data...\n");
				memcpy(base + rw_base, file_data + rw_offset, rw_filesz);
			}

			printf("Changing memory segment protection...\n");
			ret = sceKernelMprotect(base + rw_base, rw_memsz, SCE_KERNEL_PROT_CPU_RW);
			if (ret < 0) {
				EPRINTF("sceKernelMprotect(rw) failed: %d\n", ret);
				goto err;
			}

			info->rw_base = (uint64_t)(base + rw_base);
			info->rw_size = rw_memsz;
		}

		entry = LE64(ehdr->entry);
		entry -= map_base_min;

		info->entry = (elf_entry*)(base + entry);

		printf("Entrypoint: 0x%" PRIX64 "\n", (uint64_t)info->entry);

		base = NULL;
	}

	shdrs = (struct elf64_shdr*)(file_data + LE64(ehdr->shoff));
	if (LE16(ehdr->shnum) > 0) {
		printf("Parsing elf section headers...\n");

		/* do nothing */
		UNUSED(shdrs);
		UNUSED(shdr);
	}

	status = true;

err:
	if (base) {
		printf("Unmapping program memory space of size 0x%" PRIX64 "...\n", map_size);
		ret = sceKernelMunmap(base, map_size);
		if (ret < 0) {
			EPRINTF("sceKernelMunmap failed: %d\n", ret);
		}
	}

	return status;
}

static inline bool is_elf_good(struct elf64_ehdr* ehdr) {
	bool status = false;

	assert(ehdr != NULL);

	if (!(ehdr->ident[ELF_IDENT_MAG0] == '\x7F' && ehdr->ident[ELF_IDENT_MAG1] == 'E' && ehdr->ident[ELF_IDENT_MAG2] == 'L' && ehdr->ident[ELF_IDENT_MAG3] == 'F')) {
		EPRINTF("Bad magic: 0x%02X%02X%02X%02X\n", ehdr->ident[ELF_IDENT_MAG0], ehdr->ident[ELF_IDENT_MAG1], ehdr->ident[ELF_IDENT_MAG2], ehdr->ident[ELF_IDENT_MAG3]);
		goto err;
	}
	if (ehdr->ident[ELF_IDENT_CLASS] != ELF_CLASS_64) {
		EPRINTF("Unsupported class: 0x%02X\n", ehdr->ident[ELF_IDENT_CLASS]);
		goto err;
	}
	if (ehdr->ident[ELF_IDENT_DATA] != ELF_DATA_LSB) {
		EPRINTF("Unsupported data encoding: 0x%02X\n", ehdr->ident[ELF_IDENT_DATA]);
		goto err;
	}
	if (LE16(ehdr->type) != ELF_TYPE_EXEC) {
		EPRINTF("Unsupported type: 0x%" PRIX16 "\n", LE16(ehdr->type));
		goto err;
	}
	if (LE16(ehdr->machine) != ELF_MACHINE_X86_64) {
		EPRINTF("Unsupported machine: 0x%" PRIX16 "\n", LE16(ehdr->machine));
		goto err;
	}
	if (LE32(ehdr->version) != 1) {
		EPRINTF("Unsupported version: 0x%" PRIX32 "\n", LE32(ehdr->version));
		goto err;
	}
	if (LE16(ehdr->ehsize) != sizeof(struct elf64_ehdr)) {
		EPRINTF("Unexpected header size: 0x%" PRIX16 "\n", LE16(ehdr->ehsize));
		goto err;
	}
	if (LE16(ehdr->phentsize) != sizeof(struct elf64_phdr)) {
		EPRINTF("Unexpected program header size: 0x%" PRIX16 "\n", LE16(ehdr->phentsize));
		goto err;
	}
	if (LE16(ehdr->phnum) > MAX_ELF_PHDRS) {
		EPRINTF("Too many program headers.\n");
		goto err;
	}
	if (LE16(ehdr->shentsize) != sizeof(struct elf64_shdr)) {
		EPRINTF("Unexpected section header size: 0x%" PRIX16 "\n", LE16(ehdr->shentsize));
		goto err;
	}
	if (LE16(ehdr->shnum) > MAX_ELF_SHDRS) {
		EPRINTF("Too many section headers.\n");
		goto err;
	}

	status = true;

err:
	return status;
}

static void undo_privileges(void) {
	printf("Ungaining privileges...\n");
	give_power_back();
}
