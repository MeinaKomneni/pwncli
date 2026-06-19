"""堆 POC 测试的通用辅助函数。"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *

PKGS_DIR = os.path.expanduser("~/.config/kpwn/pkgs")
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def get_libc_path(version):
    return f"{PKGS_DIR}/{version}/amd64/libc6_{version}_amd64/lib/x86_64-linux-gnu/libc.so.6"


def get_binary_path(version):
    return f"{TESTS_DIR}/vuln_{version}"


def start(version):
    binary = get_binary_path(version)
    libc_path = get_libc_path(version)
    io = process(binary)
    elf = ELF(binary, checksec=False)
    libc = ELF(libc_path, checksec=False)
    return io, elf, libc


def leak_libc_base(io, libc):
    """从 /proc/pid/maps 获取 libc 基址，用于 POC 可靠性。"""
    import time
    time.sleep(0.1)
    pid = io.pid
    maps = open(f'/proc/{pid}/maps').read()
    for line in maps.split('\n'):
        if 'libc' in line and 'r--p 00000000' in line:
            return int(line.split('-')[0], 16)
    for line in maps.split('\n'):
        if 'libc' in line and 'r-xp 00000000' in line:
            return int(line.split('-')[0], 16)
    # 回退：首个 libc 映射
    for line in maps.split('\n'):
        if 'libc' in line:
            return int(line.split('-')[0], 16)
    return None


def alloc(io, idx, size):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.recvuntil(b"addr: ")
    addr = int(io.recvline().strip(), 16)
    return addr


def free(io, idx):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"idx: ", str(idx).encode())


def edit(io, idx, data):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendafter(b"data: ", data)


def show(io, idx):
    io.sendlineafter(b">", b"4")
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.recvuntil(b"data: ")


def arb_write(io, addr, data):
    io.sendlineafter(b">", b"5")
    io.sendlineafter(b"addr: ", str(addr).encode())
    io.sendlineafter(b"len: ", str(len(data)).encode())
    io.sendafter(b"data: ", data)


def do_exit(io):
    io.sendlineafter(b">", b"6")
