#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""CurrentGadgets —— 基于当前 elf/libc 的 gadget 搜索与 ROP 链构建。"""

import functools
from threading import Lock, Thread
from typing import Union

from pwn import asm, disasm, flat

from ..core.consts import Consts
from ..toolkit.gadgetbox import ElfGadgetBox, RopgadgetBox, RopperArchType, RopperBox
from ..core.log import errlog_exit, log2_ex
from ..core.packing import step_split, u64_ex
from ..core.state import gift

__all__ = [
    "CurrentGadgets",
    "load_currentgadgets_background",
    "CG",
]


class CurrentGadgets:
    __internal_gadgetbox = None
    __elf = None
    __libc = None
    __arch = None
    __find_in_elf = None
    __find_in_libc = None
    __loaded = False

    _mutex = Lock()

    @staticmethod
    def set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False):
        CurrentGadgets.__find_in_elf = find_in_elf
        CurrentGadgets.__find_in_libc = find_in_libc
        if do_initial:
            CurrentGadgets._initial_gadgetbox()

    @staticmethod
    def set_debug(debug):
        CurrentGadgets._initial_gadgetbox()
        CurrentGadgets.__internal_gadgetbox.set_debug(debug)

    @staticmethod
    def _initial_gadgetbox() -> bool:
        """从当前 elf 和 libc 获取 gadget"""
        if CurrentGadgets._mutex.acquire(blocking=True):
            CurrentGadgets._mutex.locked()

        if CurrentGadgets.__loaded:
            CurrentGadgets._mutex.release()
            return True

        elf = gift.get('elf')
        libc = gift.get('libc')
        CurrentGadgets.__elf = elf
        CurrentGadgets.__libc = libc
        __arch_mapping = {
            "i386": RopperArchType.x86,
            "amd64": RopperArchType.x86_64
        }

        if not elf and not libc:
            log2_ex("Cannot find gadget, no elf and no libc now.")
            CurrentGadgets._mutex.release()
            return False

        try:
            CurrentGadgets.__internal_gadgetbox = RopgadgetBox()
        except:
            try:
                CurrentGadgets.__internal_gadgetbox = ElfGadgetBox()
            except:
                CurrentGadgets.__internal_gadgetbox = RopperBox()

        res = False
        if elf:
            if elf.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64.")
            else:
                CurrentGadgets.__arch = elf.arch

                if CurrentGadgets.__internal_gadgetbox.box_name == "ropper":
                    CurrentGadgets.__internal_gadgetbox.add_file(
                        "elf", elf.path, __arch_mapping[elf.arch])
                else:
                    CurrentGadgets.__internal_gadgetbox.add_file(
                        "elf", elf.path, elf.arch)

                if CurrentGadgets.__elf.pie:
                    CurrentGadgets.__internal_gadgetbox.set_imagebase(
                        "elf", CurrentGadgets.__elf.address)
                res = True
        if libc:
            if libc.arch not in __arch_mapping:
                log2_ex("Unsupported arch, only for i386 and amd64..")
            else:
                CurrentGadgets.__arch = libc.arch
                if CurrentGadgets.__internal_gadgetbox.box_name == "ropper":
                    CurrentGadgets.__internal_gadgetbox.add_file(
                        "libc", libc.path, __arch_mapping[elf.arch])
                else:
                    CurrentGadgets.__internal_gadgetbox.add_file(
                        "libc", libc.path, libc.arch)

                if CurrentGadgets.__libc.pie:
                    CurrentGadgets.__internal_gadgetbox.set_imagebase(
                        "libc", CurrentGadgets.__libc.address)
                res = True

        CurrentGadgets.__loaded = res
        CurrentGadgets._mutex.release()
        return res

    @staticmethod
    def reset():
        CurrentGadgets.__internal_gadgetbox = None
        CurrentGadgets.__elf = None
        CurrentGadgets.__libc = None
        CurrentGadgets.__arch = None
        CurrentGadgets.__find_in_elf = None
        CurrentGadgets.__find_in_libc = None
        CurrentGadgets.__loaded = False
        CurrentGadgets._initial_gadgetbox()

    @staticmethod
    def __check_before_find():
        # 查找前检查 image base
        if CurrentGadgets.__find_in_elf:
            if CurrentGadgets.__elf and CurrentGadgets.__elf.pie:
                assert CurrentGadgets.__elf.address != 0, "Please set current program's base address before find gadget."

        if CurrentGadgets.__find_in_libc:
            if CurrentGadgets.__libc and CurrentGadgets.__libc.pie:
                assert CurrentGadgets.__libc.address != 0, "Please set libc's base address before find gadget."

    @staticmethod
    def _internal_find(func_name):
        if not CurrentGadgets._initial_gadgetbox():
            return 0

        CurrentGadgets.__check_before_find()

        func = getattr(CurrentGadgets.__internal_gadgetbox, func_name)
        if CurrentGadgets.__find_in_elf or (CurrentGadgets.__find_in_elf is None and (CurrentGadgets.__elf.address or CurrentGadgets.__elf.statically_linked)):
            if CurrentGadgets.__elf.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase(
                    "elf", CurrentGadgets.__elf.address)
            try:
                res = func('elf')
                return res
            except:
                pass

        if CurrentGadgets.__find_in_libc or (CurrentGadgets.__find_in_libc is None and CurrentGadgets.__libc.address):
            if CurrentGadgets.__libc.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase(
                    "libc", CurrentGadgets.__libc.address)
            res = func('libc')
            return res

        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            log2_ex(
                "Have closed both elf finder and libc finder, please call 'CurrentGadgets.set_find_area' to set a finder.")
        raise RuntimeError("Cannot find gadget using '{}'.".format(func_name))

    @staticmethod
    @functools.lru_cache(maxsize=128, typed=True)
    def find_gadget(find_str: str, find_type='asm', get_list=False) -> int:
        """ 类型：asm / opcode / string """
        if not CurrentGadgets._initial_gadgetbox():
            return 0
        CurrentGadgets.__check_before_find()
        find = find_str
        if find_type == "asm":
            find = asm(find).hex()
            func = getattr(CurrentGadgets.__internal_gadgetbox,
                           "search_opcode")
        elif find_type == "opcode":
            func = getattr(CurrentGadgets.__internal_gadgetbox,
                           "search_opcode")
        elif find_type == "string":
            func = getattr(CurrentGadgets.__internal_gadgetbox,
                           "search_string")
        else:
            errlog_exit("Unsupported find_type, only: asm / opcode / string.")

        res = None
        if CurrentGadgets.__find_in_elf or (CurrentGadgets.__find_in_elf is None and (CurrentGadgets.__elf.address or CurrentGadgets.__elf.statically_linked)):
            if CurrentGadgets.__elf.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase(
                    "elf", CurrentGadgets.__elf.address)
            try:
                return func(find, 'elf', get_list)
            except:
                pass

        if CurrentGadgets.__find_in_libc or (CurrentGadgets.__find_in_libc is None and CurrentGadgets.__libc.address):
            if CurrentGadgets.__libc.pie:
                CurrentGadgets.__internal_gadgetbox.set_imagebase(
                    "libc", CurrentGadgets.__libc.address)
            return func(find, 'libc', get_list)

        if not CurrentGadgets.__find_in_elf and not CurrentGadgets.__find_in_libc:
            errlog_exit("Have closed both elf finder and libc finder.")
        raise RuntimeError("Cannot find gadget: {}.".format(find_str))

    @staticmethod
    def syscall() -> int:
        """syscall"""
        if CurrentGadgets.__arch == "i386":
            return CurrentGadgets._internal_find('get_int80')
        elif CurrentGadgets.__arch == "amd64":
            return CurrentGadgets._internal_find('get_syscall')

    @staticmethod
    def syscall_ret() -> int:
        """syscall; ret"""
        if CurrentGadgets.__arch == "i386":
            return CurrentGadgets._internal_find('get_int80_ret')
        elif CurrentGadgets.__arch == "amd64":
            return CurrentGadgets._internal_find('get_syscall_ret')

    @staticmethod
    def ret() -> int:
        """ret"""
        return CurrentGadgets._internal_find('get_ret')

    @staticmethod
    def pop_rdi_ret() -> int:
        """pop rdi; ret"""
        return CurrentGadgets._internal_find('get_pop_rdi_ret')

    @staticmethod
    def pop_rsi_ret() -> int:
        """pop rsi; ret"""
        return CurrentGadgets._internal_find('get_pop_rsi_ret')

    @staticmethod
    def pop_rdx_ret() -> int:
        """pop rdx; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_ret')

    @staticmethod
    def pop_rdx_rbx_ret() -> int:
        """pop rdx; pop rbx; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_rbx_ret')

    @staticmethod
    def pop_rdx_xor_eax_ret() -> int:
        """pop rdx; xor eax, eax; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_xor_eax_ret')

    @staticmethod
    def pop_rdx_xor_eax_pop4_ret() -> int:
        """pop rdx; xor eax, eax; pop rbx; pop r12; pop r13; pop rbp; ret"""
        return CurrentGadgets._internal_find('get_pop_rdx_xor_eax_pop4_ret')

    @staticmethod
    def pop_rax_ret() -> int:
        """pop rax; ret"""
        return CurrentGadgets._internal_find('get_pop_rax_ret')

    @staticmethod
    def pop_rbx_ret() -> int:
        """pop rbx; ret"""
        return CurrentGadgets._internal_find('get_pop_rbx_ret')

    @staticmethod
    def pop_rcx_ret() -> int:
        """pop rcx; ret"""
        return CurrentGadgets._internal_find('get_pop_rcx_ret')

    @staticmethod
    def pop_rcx_rbx_ret() -> int:
        """pop rcx; pop rbx; ret"""
        return CurrentGadgets._internal_find('get_pop_rcx_rbx_ret')

    @staticmethod
    def pop_rbp_ret() -> int:
        """pop rbp; ret"""
        return CurrentGadgets._internal_find('get_pop_rbp_ret')

    @staticmethod
    def pop_rsp_ret() -> int:
        """pop rsp; ret"""
        return CurrentGadgets._internal_find('get_pop_rsp_ret')

    @staticmethod
    def pop_rsi_r15_ret() -> int:
        """pop rsp; ret"""
        return CurrentGadgets._internal_find('get_pop_rsi_r15_ret')

    @staticmethod
    def pop_pop_ret() -> int:
        """pop xxx; pop xxx; ret"""
        try:
            return CurrentGadgets.find_gadget('5b5dc3', 'opcode')
        except:
            pass
        try:
            return CurrentGadgets.find_gadget('5f5dc3', 'opcode')
        except:
            pass

        return CurrentGadgets.find_gadget('415e415fc3', 'opcode')

    @staticmethod
    def pop_pop_pop_ret() -> int:
        """pop xxx; pop xxx; pop xxx; ret"""
        try:
            return CurrentGadgets.find_gadget('585b5dc3', 'opcode')
        except:
            pass
        try:
            return CurrentGadgets.find_gadget('585A5BC3', 'opcode')
        except:
            pass

        return CurrentGadgets.find_gadget('415d415e415fc3', 'opcode')

    @staticmethod
    def pop_pop_pop_pop_ret() -> int:
        """pop xxx; pop xxx; pop xxx; pop xxx; ret"""
        res = CurrentGadgets.find_gadget('415C415D415E415FC3', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def pop_pop_pop_pop_pop_ret() -> int:
        """pop xxx; pop xxx; pop xxx; pop xxx; pop xxx; ret"""
        res = CurrentGadgets.find_gadget('5D415C415D415E415FC3', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def pop_pop_pop_pop_pop_pop_ret() -> int:
        """pop xxx; pop xxx; pop xxx; pop xxx; pop xxx; ret"""

        res = CurrentGadgets.find_gadget('5B5D415C415D415E415FC3', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def mov_rsp_rdx_ret() -> int:
        """mov rsp, rdx; ret"""
        res = CurrentGadgets.find_gadget('4889D4C3', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def magic_gadget() -> int:
        """add dword ptr [rbp - 0x3d], ebx; ret"""
        if not CurrentGadgets._initial_gadgetbox():
            return 0
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return CurrentGadgets._internal_find('get_magic_gadget')

    @staticmethod
    def leave_ret() -> int:
        """leave; ret"""
        return CurrentGadgets._internal_find('get_leave_ret')

    @staticmethod
    def bin_sh() -> int:
        """/bin/sh"""
        return CurrentGadgets._internal_find('get_bin_sh')

    @staticmethod
    def sh() -> int:
        """sh"""
        return CurrentGadgets._internal_find('get_sh')

    @staticmethod
    def stack_pivot_from_rdi_gadget() -> int:
        """mov rbp, qword ptr [rdi + 0x48];

        mov rax, qword ptr [rbp + 0x18]; 

        lea r13, [rbp + 0x10]; 

        mov dword ptr [rbp + 0x10], 0; 

        mov rdi, r13; 

        call qword ptr [rax + 0x28];"""
        res = CurrentGadgets.find_gadget(
            '488B6F48488B45184C8D6D10C74510000000004C89EFFF5028', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def control_rdx_from_rdi_gadget() -> int:
        """mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20]"""
        res = CurrentGadgets.find_gadget('488B570848890424FF5220  ', 'opcode')
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def control_rdx_from_rdi_gadget_payload(rdi_addr: int, ropchain: Union[bytes, list, tuple, dict]) -> bytes:
        """mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20] 的 rop payload"""
        if not CurrentGadgets._initial_gadgetbox():
            return 0
        layout = [
            CurrentGadgets.pop_pop_pop_pop_ret(),
            rdi_addr,
            0,
            0,
            CurrentGadgets.mov_rsp_rdx_ret(),
            ropchain
        ]
        return flat(layout)

    @staticmethod
    def control_rdx_from_rdi_gadget_payload_system_binsh(rdi_addr: int, system_addr: int) -> bytes:
        """mov rdx, [rdi + 8]; mov [rsp], rax; call [rdx + 0x20] 执行 system(/bin/sh) 的 rop payload"""
        if not CurrentGadgets._initial_gadgetbox():
            return 0
        layout = [
            0x68732f6e69622f,
            rdi_addr-0x10,
            system_addr
        ]
        return flat(layout)

    @staticmethod
    def stack_pivot_from_rdi_gadget_rdi_payload(rdi_addr, ropchain: bytes) -> bytes:
        """Gadget: mov rbp, qword ptr [rdi + 0x48];
        mov rax, qword ptr [rbp + 0x18]; 
        lea r13, [rbp + 0x10]; 
        mov dword ptr [rbp + 0x10], 0; 
        mov rdi, r13; 
        call qword ptr [rax + 0x28];

        为 stack_pivot_from_rdi_gadget 设置 rdi 的 payload 数据。需保证 rdi 有足够空间，至少 'len(ropchain) + 0x48'

        ropchain 为：

        pop rdi; ret;

        stack_pivot_from_rdi_gadget_rdi_payload(XXX);

        stack_pivot_from_rdi_gadget()
        """
        res = flat({
            0x8: CurrentGadgets.pop_pop_ret(),
            0x18: rdi_addr,
            0x20: CurrentGadgets.pop_pop_ret(),
            0x28: CurrentGadgets.leave_ret(),
            0x38: CurrentGadgets.pop_pop_ret(),
            0x48: rdi_addr,
            0x50: ropchain
        })
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def stack_pivot_from_rdi_gadget_rdi_payload_ex(rdi_addr, ropchain_or_funcaddr: Union[int, bytes],
                                                   rop_rdi_reg: int, rop_rsi_reg: int = 0,  rop_rdx_reg: int = 0) -> bytes:
        """Gadget: mov rbp, qword ptr [rdi + 0x48];
        mov rax, qword ptr [rbp + 0x18]; 
        lea r13, [rbp + 0x10]; 
        mov dword ptr [rbp + 0x10], 0; 
        mov rdi, r13; 
        call qword ptr [rax + 0x28];

        为 stack_pivot_from_rdi_gadget 设置 rdi 的 payload 数据。需保证 rdi 有足够空间，至少 '0x50'

        例如：stack_pivot_from_rdi_gadget_rdi_payload_ex(XXXX, write_addr, 1, buf, 0x30) 或 stack_pivot_from_rdi_gadget_rdi_payload_ex(XXXX, buf, puts_addr)

        ropchain 为：

        pop rdi; ret;

        stack_pivot_from_rdi_gadget_rdi_payload_ex(XXX);

        stack_pivot_from_rdi_gadget()
        """
        if not rop_rdx_reg:
            assert isinstance(ropchain_or_funcaddr, int), "must be int!"
            layout = [
                CurrentGadgets.pop_pop_ret(),
                0,
                rdi_addr + 0x18,
                CurrentGadgets.pop_rdi_ret(),
                rop_rdi_reg,
                CurrentGadgets.__try_get_rsi_gadget(rop_rsi_reg),
                ropchain_or_funcaddr,
                CurrentGadgets.leave_ret(),
                rdi_addr - 8
            ]
        else:
            layout = [
                CurrentGadgets.pop_pop_ret(),
                0,
                rdi_addr + 0x28,
                CurrentGadgets.pop_rdi_ret(),
                rop_rdi_reg,
                CurrentGadgets.__try_get_rsi_gadget(rop_rsi_reg),
                # pop rdx, pop rcx, pop rbx, ret
                CurrentGadgets.find_gadget('5A595BC3', 'opcode'),
                rop_rdx_reg,
                rdi_addr - 0x8,
                CurrentGadgets.leave_ret(),
                ropchain_or_funcaddr
            ]
        res = flat(layout)
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        return res

    @staticmethod
    def write8bytes_at_addr(addr: int, number: int) -> bytes:
        """ *addr = number """
        if not CurrentGadgets._initial_gadgetbox():
            return None
        assert CurrentGadgets.__arch == "amd64", "only for amd64"
        # mov qword ptr [rax], rdi; ret;
        layout = [
            CurrentGadgets.pop_rax_ret(),
            addr,
            CurrentGadgets.pop_rdi_ret(),
            number,
            CurrentGadgets.find_gadget('488938C3', 'opcode')
        ]
        try:
            return flat(layout)
        except:
            pass
        # mov qword ptr [rax], rdx; ret;
        layout = [
            CurrentGadgets.__try_get_rdx_gadget(number),
            CurrentGadgets.pop_rax_ret(),
            addr,
            CurrentGadgets.find_gadget('488910C3', 'opcode')
        ]
        return flat(layout)

    @staticmethod
    def write_at_addr(addr: int, payload: bytes) -> bytes:
        res = []
        for curp in step_split(payload, 8):
            num = u64_ex(curp)
            res.append(CurrentGadgets.write8bytes_at_addr(addr, num))
            addr += 8
        return flat(res)

    @staticmethod
    def copy_byte2byte(src_addr: int, dst_addr: int, length: int, do_cld=True) -> bytes:
        """使用 rep 指令复制数据"""
        if not CurrentGadgets._initial_gadgetbox():
            return None

        layout = [
            CurrentGadgets.__try_get_rsi_gadget(src_addr),
            CurrentGadgets.pop_rdi_ret(),
            dst_addr,
            CurrentGadgets.__try_get_rcx_gadget(length)
        ]
        if do_cld:
            layout.append(CurrentGadgets.find_gadget('fcc3', 'opcode'))

        layout.append(CurrentGadgets.find_gadget('f3a4c3', 'opcode'))

        return flat(layout)

    @staticmethod
    def __try_get_rdx_gadget(rdx_val, rbx_val=0) -> list:
        try:
            return [CurrentGadgets.pop_rdx_ret(), rdx_val]
        except:
            pass
        try:
            return [CurrentGadgets.pop_rdx_rbx_ret(), rdx_val, rbx_val]
        except:
            pass
        try:
            return [CurrentGadgets.pop_rdx_xor_eax_ret(), rdx_val]
        except:
            pass
        return [CurrentGadgets.pop_rdx_xor_eax_pop4_ret(), rdx_val, 0, 0, 0, 0]

    @staticmethod
    def __try_get_rcx_gadget(rcx_val, rbx_val=0) -> list:
        try:
            return [CurrentGadgets.pop_rcx_ret(), rcx_val]
        except:
            return [CurrentGadgets.pop_rcx_rbx_ret(), rcx_val, rbx_val]

    @staticmethod
    def __try_get_rsi_gadget(rsi_val, r15_val=0) -> list:
        try:
            return [CurrentGadgets.pop_rsi_ret(), rsi_val]
        except:
            return [CurrentGadgets.pop_rsi_r15_ret(), rsi_val, r15_val]

    @staticmethod
    def __inner_chain(i386_num, syscall_num, para1, para2=None, para3=None) -> bytes:
        if not CurrentGadgets._initial_gadgetbox():
            return None
        if CurrentGadgets.__arch == "i386":
            if para1 < 0:
                para1 += 1 << 32
            layout = [
                CurrentGadgets.pop_rbx_ret(),
                para1
            ]
            if para2 is not None:
                layout.append(CurrentGadgets.__try_get_rcx_gadget(para2))

            if para3 is not None:
                layout.append(
                    CurrentGadgets.__try_get_rdx_gadget(para3, para1))

            layout.append(CurrentGadgets.pop_rax_ret())
            layout.append(i386_num)
            layout.append(CurrentGadgets.syscall_ret())
            return flat(layout)

        elif CurrentGadgets.__arch == "amd64":
            if para1 < 0:
                para1 += 1 << 64
            layout = [
                CurrentGadgets.pop_rdi_ret(),
                para1
            ]
            if para2 is not None:
                layout.append(CurrentGadgets.__try_get_rsi_gadget(para2))

            if para3 is not None:
                layout.append(CurrentGadgets.__try_get_rdx_gadget(para3))

            layout.append(CurrentGadgets.pop_rax_ret())
            layout.append(syscall_num)
            layout.append(CurrentGadgets.syscall_ret())
            return flat(layout)
        else:
            errlog_exit("Unsupported arch: {}".format(CurrentGadgets.__arch))

    @staticmethod
    def syscall_chain(syscall_num, para1, para2=None, para3=None) -> bytes:
        return CurrentGadgets.__inner_chain(syscall_num, syscall_num, para1, para2, para3)

    @staticmethod
    def execve_chain(bin_sh_addr=None) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.EXECVE, Consts.syscall.amd64.EXECVE, bin_sh_addr or CurrentGadgets.bin_sh(), 0, 0)

    @staticmethod
    def mprotect_chain(va, length=0x1000, prog=7) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.MPROTECT, Consts.syscall.amd64.MPROTECT, va, length, prog)

    @staticmethod
    def open_chain(fileaddr, flag=0, mode=None) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.OPEN, Consts.syscall.amd64.OPEN, fileaddr, flag, mode)

    @staticmethod
    def openat_chain(fileaddr, flag=0) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.OPENAT, Consts.syscall.amd64.OPENAT, -100, fileaddr, flag)

    @staticmethod
    def read_chain(fd, buf, length) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.READ, Consts.syscall.amd64.READ, fd, buf, length)

    @staticmethod
    def write_chain(fd, buf, length) -> bytes:
        return CurrentGadgets.__inner_chain(Consts.syscall.i386.WRITE, Consts.syscall.amd64.WRITE, fd, buf, length)

    @staticmethod
    def orw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30) -> bytes:
        return CurrentGadgets.open_chain(flag_addr) + \
            CurrentGadgets.read_chain(flag_fd, buf_addr or flag_addr, buf_len) + \
            CurrentGadgets.write_chain(
                write_fd, buf_addr or flag_addr, buf_len)

    @staticmethod
    def otrw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30) -> bytes:
        return CurrentGadgets.openat_chain(flag_addr) + \
            CurrentGadgets.read_chain(flag_fd, buf_addr or flag_addr, buf_len) + \
            CurrentGadgets.write_chain(
                write_fd, buf_addr or flag_addr, buf_len)

    @staticmethod
    def write_by_magic(write_addr: int, ori: int, expected: int, short=True) -> bytes:
        if not CurrentGadgets._initial_gadgetbox():
            return None
        if CurrentGadgets.__arch == "amd64":
            if short:
                return flat([
                    CurrentGadgets.find_gadget(
                        "5b5d415c415d415e415fc3", 'opcode'),
                    expected - ori if expected > ori else expected - ori + 0x100000000,
                    write_addr+0x3d, 0, 0, 0, 0,
                    CurrentGadgets.magic_gadget()
                ])
            else:
                return flat([
                    CurrentGadgets.find_gadget(
                        "4883c4085b5d415c415d415e415fc3", 'opcode'),
                    0,
                    expected - ori if expected > ori else expected - ori + 0x100000000,
                    write_addr+0x3d, 0, 0, 0, 0,
                    CurrentGadgets.magic_gadget()
                ])

        else:
            errlog_exit("Only used for amd64!")

    @staticmethod
    def ret2csu(edi: int, rsi: int, rdx: int, call_array_addr: int,
                rbx: int = 0, rbp: int = 1, short=True) -> bytes:
        if not CurrentGadgets._initial_gadgetbox():
            return None
        if CurrentGadgets.__arch != "amd64":
            errlog_exit("Only used for amd64!")
        if short:
            startaddr = CurrentGadgets.find_gadget(
                "5b5d415c415d415e415fc3", 'opcode')
            another = startaddr - 26

        else:
            startaddr = CurrentGadgets.find_gadget(
                "4883c4085b5d415c415d415e415fc3", 'opcode')
            another = startaddr - 22
        rdata = CurrentGadgets.__elf.read(another, 13)

        dis_res = disasm(rdata, arch="amd64").splitlines()
        assert len(dis_res) == 4 and "mov" in dis_res[0] and "mov" in dis_res[1] and "mov" in dis_res[
            2] and "call" in dis_res[3], "You need build csu ropchain manually."

        layout = [startaddr]
        if not short:
            layout.append(0)
        layout.append(rbx)
        layout.append(rbp)

        oldlen = len(layout)

        for reg in ['r12', 'r13', 'r14', 'r15']:
            for x in dis_res:
                if reg in x:
                    if 'mov' in x:
                        if 'di' in x:
                            layout.append(edi)
                        elif 'si' in x:
                            layout.append(rsi)
                        elif 'dx' in x:
                            layout.append(rdx)
                    else:
                        layout.append(call_array_addr)

        newlen = len(layout)
        assert newlen - oldlen == 4, "You need build csu ropchain manually."

        layout.append(another)
        layout += [0]*7
        return flat(layout)


def load_currentgadgets_background(find_in_elf=True, find_in_libc=True):
    Thread(target=CurrentGadgets.set_find_area, args=(
        find_in_elf, find_in_libc, True), daemon=True).start()


CG = CurrentGadgets
