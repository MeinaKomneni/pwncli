"""运行时地址接收与解析：从 tube 收 libc 地址、收 0x 地址、读 /proc/pid/maps。"""

import re
import subprocess
import time

from ..core.log import errlog_exit, warn_ex
from ..core.packing import int16_ex, u32_ex, u64_ex

__all__ = [
    "recv_libc_addr",
    "recv_addr_startswith_0x",
    "get_segment_base_addr_by_proc_maps",
]


def recv_libc_addr(io, *, bits=64, offset=0, timeout=5) -> int:
    """在 amd64 下接收到 '\x7f'、i386 下接收到 '\xf7' 时计算 libc 基址地址。

    Args:
        p (tube): tube 对象。
        bits (int, optional): 32 或 64，默认为 64。
        offset (int, optional): 用于辅助获取 libc 基址，默认为 0。

    Raises:
        RuntimeError: 若 3 秒内未接收到与 libc 地址相关的字节则抛出。

    Returns:
        int: libc 地址
    """
    assert bits == 32 or bits == 64
    contains = b"\x7f" if bits == 64 else b"\xf7"
    m = io.recvuntil(contains, timeout=timeout)
    if contains not in m:
        raise RuntimeError("Cannot get libc addr")
    if bits == 32:
        return u32_ex(m[-4:]) - offset
    else:
        return u64_ex(m[-6:]) - offset

def recv_addr_startswith_0x(io, *, prefix="", suffix="", has_0x=True, timeout=5) -> int:
    """接收以 0x 或 0X 开头的地址数据。

    Args:
        io (tube): tube 对象。

    Raises:
        RuntimeError: 若无法接收到地址则抛出。

    Returns:
        int: 某个地址
    """
    if len(suffix) == 0:
        suffix = "[^0-9A-Fa-f]"
    if has_0x:
        mid = "(0[xX][0-9A-Fa-f]+)"
    else:
        mid = "([0-9A-Fa-f]+)"
    m = io.recvregex(prefix + mid + suffix, capture=True,timeout=timeout)
    if not m:
        raise RuntimeError("Cannot get 0x???? addr")
    m = m.group(1)
    if has_0x and (b"0x" not in m) and (b"0x" not in m):
        raise RuntimeError("Cannot get 0x???? addr")
    return int16_ex(m)


def get_segment_base_addr_by_proc_maps(pid:int, filename:str=None) -> dict:
    """读取 /proc/pid/maps 文件获取基址。返回的字典包含键：'code'、'libc'、'ld'、'stack'、'heap'、'vdso'。

    Args:
        pid (int): 进程 pid。
        filename (str, optional): 用于获取 code 基址的文件名，默认为 None。

    Returns:
        dict: 所有段地址。Key: str，Val: int。
    """
    assert isinstance(pid, int), "error type!"
    res = None
    try:
        res = subprocess.check_output(["cat", "/proc/{}/maps".format(pid)]).decode()
        if "/libc" not in res or "/ld" not in res: # 再次尝试
            # 等待 ld 加载 libc
            time.sleep(1)
            try:
                res = subprocess.check_output(["cat", "/proc/{}/maps".format(pid)]).decode()
            except:
                errlog_exit("cat /proc/{}/maps faild!".format(pid))

    except:
        errlog_exit("cat /proc/{}/maps faild!".format(pid))
    _d = {}
    if not res:
        warn_ex("'cat /proc/{}/maps' gets empty result, are you sure the process is alive?".format(pid))
        return _d
    res = res.split("\n")
    code_flag = 0
    libc_flag = 0
    ld_flag = 0

    for r in res:
        rc = re.compile(r"^([0-9a-f]{6,14})-([0-9a-f]{6,14})", re.S)
        rc = rc.findall(r)
        if len(rc) != 1 or len(rc[0]) != 2:
            continue
        start_addr = int(rc[0][0], base=16)
        end_addr = int(rc[0][1], base=16)
        if (filename is not None) and (not code_flag) and r.endswith(filename):
            code_flag = 1
            _d['code'] = start_addr
        elif (not libc_flag) and ("/libc" in r):
            libc_flag = 1
            _d['libc'] = start_addr
        elif (not ld_flag) and ("/ld" in r):
            ld_flag = 1
            _d['ld'] = start_addr
        elif "heap" in r:
            _d['heap'] = start_addr
        elif "stack" in r:
            _d['stack'] = start_addr
        elif "vdso" in r:
            _d['vdso'] = start_addr
    return _d
