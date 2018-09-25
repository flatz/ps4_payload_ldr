WINE = wine
WINE_PATH_TOOL = winepath

CC = $(WINE) orbis-clang
LD = $(WINE) orbis-ld
OBJCOPY = $(WINE) orbis-objcopy
PUBCMD = $(WINE) orbis-pub-cmd

OBJDIR = obj
BLDDIR = build
MODDIR = sce_module

TARGET = payload_ldr
LIBS = -lSceNet_stub_weak -lSceNetCtl_stub_weak -lSceSystemService_stub_weak
SDK_MODULES = libc.prx libSceFios2.prx

ASM_SRCS = syscalls.S
C_SRCS = jailbreak.c main.c network.c server.c util.c

COMMON_FLAGS = -Wall
COMMON_FLAGS += -fdiagnostics-color=always
COMMON_FLAGS += -I $(SCE_ORBIS_SDK_DIR)/target/include -I $(SCE_ORBIS_SDK_DIR)/target/include/common
COMMON_FLAGS += -DNDEBUG
COMMON_FLAGS += -g

CFLAGS = $(COMMON_FLAGS)
CFLAGS += -std=c11
CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-unused-label -Werror=implicit-function-declaration
CFLAGS += -fno-strict-aliasing
CFLAGS += -fPIC
CFLAGS += -O3

ASFLAGS = $(COMMON_FLAGS)

LDFLAGS = -Wl,--strip-unused-data
LDFLAGS += -L $(SCE_ORBIS_SDK_DIR)/target/lib

OBJS = $(addprefix $(OBJDIR)/,$(ASM_SRCS:.S=.S.o) $(C_SRCS:.c=.c.o))

.PHONY: all clean

all: post-build

pre-build:
	@mkdir -p $(MODDIR) $(OBJDIR) $(BLDDIR)
	@for filename in $(SDK_MODULES); do \
		if [ ! -f "$(MODDIR)/$$filename" ]; then \
			echo Copying $$filename...; \
			cp "`$(WINE_PATH_TOOL) -u \"$(SCE_ORBIS_SDK_DIR)/target/sce_module/$$filename\"`" $(MODDIR)/; \
		fi; \
	done;

post-build: main-build

main-build: pre-build
	@$(MAKE) --no-print-directory pkg

eboot: $(OBJS)
	$(CC) $(LDFLAGS) -o $(BLDDIR)/$(TARGET).elf $^ $(LIBS)

$(OBJDIR)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

$(OBJDIR)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

sfo:
	$(PUBCMD) sfo_create sce_sys/param.sfx $(BLDDIR)/param.sfo

pkg: sfo eboot
	$(PUBCMD) img_create $(TARGET).gp4 $(BLDDIR)/$(TARGET).pkg

clean:
	@rm -rf $(OBJDIR) $(BLDDIR)
