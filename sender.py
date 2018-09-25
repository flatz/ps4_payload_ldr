#!/usr/bin/env python2.7

import sys, os, socket
import struct
import argparse
import atexit
import re

def align_up(x, alignment):
	return (x + (alignment - 1)) & ~(alignment - 1)

def align_down(x, alignment):
	return x & ~(alignment - 1)

def check_file_magic(f, expected_magic):
	old_offset = f.tell()
	try:
		magic = f.read(len(expected_magic))
	except:
		return False
	finally:
		f.seek(old_offset)
	return magic == expected_magic

def parse_net_address(address):
	matches = re.match('^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\:([0-9]{1,5})$', address)
	if matches is None:
		return None

	host = '{0}.{1}.{2}.{3}'.format(int(matches.group(1), 10), int(matches.group(2), 10), int(matches.group(3), 10), int(matches.group(4), 10))
	port = int(matches.group(5), 10)

	return (host, port)

class ElfProgramHeader64(object):
	FMT = '<2I6Q'

	PT_NULL = 0x0
	PT_LOAD = 0x1
	PT_SCE_DYNLIBDATA = 0x61000000
	PT_SCE_RELRO = 0x61000010
	PT_SCE_COMMENT = 0x6FFFFF00
	PT_SCE_VERSION = 0x6FFFFF01

	PF_X = 0x1
	PF_W = 0x2
	PF_R = 0x4
	PF_RX = PF_R | PF_X
	PF_RW = PF_R | PF_W

	def __init__(self):
		self.type = None
		self.flags = None
		self.offset = None
		self.vaddr = None
		self.paddr = None
		self.file_size = None
		self.mem_size = None
		self.align = None

	def load(self, f):
		data = f.read(struct.calcsize(ElfProgramHeader64.FMT))
		if len(data) != struct.calcsize(ElfProgramHeader64.FMT):
			return False
		self.type, self.flags, self.offset, self.vaddr, self.paddr, self.file_size, self.mem_size, self.align = struct.unpack(ElfProgramHeader64.FMT, data)
		return True

class ElfSectionHeader64(object):
	FMT = '<2I4Q2I2Q'

	def __init__(self):
		self.name = None
		self.type = None
		self.flags = None
		self.addr = None
		self.offset = None
		self.size = None
		self.link = None
		self.info = None
		self.align = None
		self.entry_size = None

	def load(self, f):
		data = f.read(struct.calcsize(ElfSectionHeader64.FMT))
		if len(data) != struct.calcsize(ElfSectionHeader64.FMT):
			return False
		self.name, self.type, self.flags, self.addr, self.offset, self.size, self.link, self.info, self.align, self.entry_size = struct.unpack(ElfSectionHeader64.FMT, data)
		return True

class ElfFile64(object):
	MAGIC = '\x7FELF'

	FMT = '<4s5B6xB2HI3QI6H'

	CLASS_NONE = 0
	CLASS_64 = 2

	DATA_NONE = 0
	DATA_LSB = 1

	VERSION_CURRENT = 1

	MACHINE_X86_64 = 0x3E

	def __init__(self):
		self.magic = None
		self.cls = None
		self.encoding = None
		self.version = None
		self.os_abi = None
		self.abi_version = None
		self.nident_size = None
		self.type = None
		self.machine = None
		self.version = None
		self.entry = None
		self.phdr_offset = None
		self.shdr_offset = None
		self.flags = None
		self.ehdr_size = None
		self.phdr_size = None
		self.phdr_count = None
		self.shdr_size = None
		self.shdr_count = None
		self.shdr_strtable_idx = None

		self.phdrs = None
		self.shdrs = None

	def check(self, f):
		old_offset = f.tell()
		try:
			result = check_file_magic(f, ElfFile64.MAGIC)
		except:
			return False
		finally:
			f.seek(old_offset)
		return result

	def load(self, f):
		data = f.read(struct.calcsize(ElfFile64.FMT))
		if len(data) != struct.calcsize(ElfFile64.FMT):
			print('error: unable to read header #1')
			return False

		self.magic, self.cls, self.encoding, self.legacy_version, self.os_abi, self.abi_version, self.nident_size, self.type, self.machine, self.version, self.entry, self.phdr_offset, self.shdr_offset, self.flags, self.ehdr_size, self.phdr_size, self.phdr_count, self.shdr_size, self.shdr_count, self.shdr_strtable_idx = struct.unpack(ElfFile64.FMT, data)
		if self.magic != ElfFile64.MAGIC:
			print('error: invalid magic: 0x{0:08X}'.format(self.magic))
			return False
		if self.encoding != ElfFile64.DATA_LSB:
			print('error: unsupported encoding: 0x{0:02X}'.format(self.encoding))
			return False
		if self.legacy_version != ElfFile64.VERSION_CURRENT:
			raise Exception('Unsupported version: 0x{0:x}'.format(self.version))
		if self.cls != ElfFile64.CLASS_64:
			print('error: unsupported class: 0x{0:02X}'.format(self.cls))
			return False
		if self.machine != ElfFile64.MACHINE_X86_64:
			print('error: unexpected machine: 0x{0:X}'.format(self.machine))
			return False
		if self.ehdr_size != struct.calcsize(ElfFile64.FMT):
			print('error: invalid elf header size: 0x{0:X}'.format(self.ehdr_size))
			return False
		if self.phdr_size > 0 and self.phdr_size != struct.calcsize(ElfProgramHeader64.FMT):
			print('error: invalid program header size: 0x{0:X}'.format(self.phdr_size))
			return False
		if self.shdr_size > 0 and self.shdr_size != struct.calcsize(ElfSectionHeader64.FMT):
			print('error: invalid section header size: 0x{0:X}'.format(self.shdr_size))
			return False

		self.phdrs = []
		for i in xrange(self.phdr_count):
			phdr = ElfProgramHeader64()
			f.seek(self.phdr_offset + i * self.phdr_size)
			if not phdr.load(f):
				print('error: unable to load program header #{0}'.format(i))
				return False
			self.phdrs.append(phdr)

		self.shdrs = []
		#if self.shdr_size > 0:
		#	for i in xrange(self.shdr_count):
		#		shdr = ElfSectionHeader64()
		#		f.seek(self.shdr_offset + i * self.shdr_size)
		#		if not shdr.load(f):
		#			print('error: unable to load section header #{0}'.format(i))
		#			return False
		#		self.shdrs.append(shdr)

		return True

def endpoint_type(val):
	address = parse_net_address(val.strip())
	if address is None:
		raise argparse.ArgumentTypeError('invalid endpoint address: {0}'.format(val))
	return address

class MyParser(argparse.ArgumentParser):
	def error(self, message):
		self.print_help()
		sys.stderr.write('\nerror: {0}\n'.format(message))
		sys.exit(2)

def cleanup():
	if sock is None:
		return
	print('closing connection...')
	sock.shutdown(socket.SHUT_RDWR)
	sock.close()

FLAG_DONT_STOP   = (1 << 0)
FLAG_USE_SPAWN   = (1 << 1)
FLAG_NEED_ROOT   = (1 << 2)
FLAG_NEED_UNJAIL = (1 << 3)

MAX_PATH_LENGTH = 256

parser = MyParser(description='payload sender')
parser.add_argument('--endpoint', type=endpoint_type, help='ldr address & port')
parser.add_argument('--dont-stop', action='store_true', default=False, help='don\'t stop server after loading')
parser.add_argument('--root', action='store_true', default=False, help='perform rooting')
parser.add_argument('--unjail', action='store_true', default=False, help='perform jailbreak')
parser.add_argument('--override-path', type=str, default='', help='override file path')
parser.add_argument('input', type=str, help='self file')
parser.add_argument('self_args', nargs='*', help='self arguments')

if len(sys.argv) == 1:
	parser.print_usage()
	sys.exit(1)

args = parser.parse_args()

elf_file_path = args.input
if not os.path.isfile(elf_file_path):
	parser.error('invalid elf file: {0}'.format(elf_file_path))

if args.endpoint is None:
	parser.error('payload ldr address should be specified')
endpoint_host, endpoint_port = args.endpoint

print('checking file format: {0}'.format(elf_file_path))
with open(elf_file_path, 'rb') as f:
	if check_file_magic(f, '\x7FELF'):
		print('elf file detected')
		fmt = 'elf'
	elif check_file_magic(f, '\x4F\x15\x3D\x1D'):
		print('self file detected')
		fmt = 'self'
	else:
		print('error: unknown file format')
		sys.exit()

if fmt == 'elf':
	print('loading elf file: {0}'.format(elf_file_path))
	with open(elf_file_path, 'rb') as f:
		elf = ElfFile64()
		if not elf.check(f):
			print('error: invalid elf file format')
			sys.exit()
		if not elf.load(f):
			print('error: unable to load elf file')
			sys.exit()
		f.seek(0)
		data = f.read()
		data_size = len(data)

	remote_file_path = '\0' * MAX_PATH_LENGTH
elif fmt == 'self':
	remote_file_path = args.override_path.strip()
	if len(remote_file_path) == 0:
		remote_file_path = os.path.split(elf_file_path)[1]
	if len(remote_file_path) == 0 or len(remote_file_path) >= MAX_PATH_LENGTH:
		print('error: bad self file path')
		sys.exit()
	remote_file_path = remote_file_path.ljust(MAX_PATH_LENGTH, '\0')

	print('loading self file: {0}'.format(elf_file_path))
	with open(elf_file_path, 'rb') as f:
		data = f.read()
		data_size = len(data)

if len(args.self_args) > 0:
	extra_data = '\0'.join(args.self_args)
else:
	extra_data = ''

print('trying to connect to endpoint...')
try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((endpoint_host, endpoint_port))
except socket.error as e:
	print('error: unable to connect to endpoint')
	sys.exit()

atexit.register(cleanup)

print('sending file...')
try:
	flags = 0
	if args.dont_stop:
		flags |= FLAG_DONT_STOP
		extra_size = 0
	if fmt == 'self':
		flags |= FLAG_USE_SPAWN
	if args.root:
		flags |= FLAG_NEED_ROOT
	if args.unjail:
		flags |= FLAG_NEED_UNJAIL
	extra_size = len(extra_data)
	hdr = struct.pack('<256sQII', remote_file_path, data_size, extra_size, flags)
	sock.sendall(hdr + data + extra_data)
except socket.error as e:
	print('error: unable to send file')
	sys.exit()

print('receiving acknowledge...')
try:
	ack = sock.recv(struct.calcsize('I'))
	if len(ack) != struct.calcsize('I'):
		print('error: insufficient data received (expected: 0x{0:X}, got: 0x{1:X})'.format(struct.calcsize('I'), len(ack)))
		sys.exit()
	ack = struct.unpack('<I', ack)[0]
	if ack != 0xABADC0FE:
		print('error: unexpected acknowledge flag 0x{0:08X}'.format(ack))
		sys.exit()
except socket.error as e:
	print('error: unable to send file')
	sys.exit()

print('closing connection...')
sock.shutdown(socket.SHUT_RDWR)
sock.close()
sock = None

print('done')
