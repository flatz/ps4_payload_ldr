#pragma once

#include "common.h"

#define ELF_IDENT_SIZE 0x10

#define ELF_IDENT_MAG0  0
#define ELF_IDENT_MAG1  1
#define ELF_IDENT_MAG2  2
#define ELF_IDENT_MAG3  3
#define ELF_IDENT_CLASS 4
#define ELF_IDENT_DATA  5

#define ELF_CLASS_64 2
#define ELF_DATA_LSB 1

#define ELF_TYPE_NONE 0
#define ELF_TYPE_EXEC 2

#define ELF_MACHINE_X86_64 0x3E

#define ELF_PHDR_TYPE_NULL 0x0
#define ELF_PHDR_TYPE_LOAD 0x1
#define ELF_PHDR_TYPE_SCE_DYNLIBDATA 0x61000000
#define ELF_PHDR_TYPE_SCE_RELRO 0x61000010
#define ELF_PHDR_TYPE_SCE_COMMENT 0x6FFFFF00
#define ELF_PHDR_TYPE_SCE_VERSION 0x6FFFFF01

#define ELF_PHDR_FLAG_X 0x1
#define ELF_PHDR_FLAG_W 0x2
#define ELF_PHDR_FLAG_R 0x4

#define ELF_ET_EXEC 0x2
#define ELF_ET_SCE_EXEC 0xFE00
#define ELF_ET_SCE_EXEC_ASLR 0xFE10
#define ELF_ET_SCE_DYNAMIC 0xFE18

typedef uint16_t elf32_half_t;
typedef uint32_t elf32_word_t;
typedef uint32_t elf32_off_t;
typedef uint32_t elf32_addr_t;

typedef uint16_t elf64_half_t;
typedef uint32_t elf64_word_t;
typedef uint64_t elf64_xword_t;
typedef uint64_t elf64_off_t;
typedef uint64_t elf64_addr_t;

struct elf32_ehdr {
	uint8_t ident[ELF_IDENT_SIZE];
	elf32_half_t type;
	elf32_half_t machine;
	elf32_word_t version;
	elf32_addr_t entry;
	elf32_off_t phoff;
	elf32_off_t shoff;
	elf32_word_t flags;
	elf32_half_t ehsize;
	elf32_half_t phentsize;
	elf32_half_t phnum;
	elf32_half_t shentsize;
	elf32_half_t shnum;
	elf32_half_t shstrndx;
};

struct elf64_ehdr {
	uint8_t ident[ELF_IDENT_SIZE];
	elf64_half_t type;
	elf64_half_t machine;
	elf64_word_t version;
	elf64_addr_t entry;
	elf64_off_t phoff;
	elf64_off_t shoff;
	elf64_word_t flags;
	elf64_half_t ehsize;
	elf64_half_t phentsize;
	elf64_half_t phnum;
	elf64_half_t shentsize;
	elf64_half_t shnum;
	elf64_half_t shstrndx;
};

struct elf32_phdr {
	elf32_word_t type;
	elf32_off_t offset;
	elf32_addr_t vaddr;
	elf32_addr_t paddr;
	elf32_word_t filesz;
	elf32_word_t memsz;
	elf32_word_t flags;
	elf32_word_t align;
};

struct elf64_phdr {
	elf64_word_t type;
	elf64_word_t flags;
	elf64_off_t offset;
	elf64_addr_t vaddr;
	elf64_addr_t paddr;
	elf64_xword_t filesz;
	elf64_xword_t memsz;
	elf64_xword_t align;
};

struct elf32_shdr {
	elf32_word_t name;
	elf32_word_t type;
	elf32_word_t flags;
	elf32_addr_t addr;
	elf32_off_t offset;
	elf32_word_t size;
	elf32_word_t link;
	elf32_word_t info;
	elf32_word_t addralign;
	elf32_word_t entsize;
};

struct elf64_shdr {
	elf64_word_t name;
	elf64_word_t type;
	elf64_xword_t flags;
	elf64_addr_t addr;
	elf64_off_t offset;
	elf64_xword_t size;
	elf64_word_t link;
	elf64_word_t info;
	elf64_xword_t addralign;
	elf64_xword_t entsize;
};
