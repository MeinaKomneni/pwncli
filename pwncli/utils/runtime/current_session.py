#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""操作当前会话(gift)的 io 收发、段基址读写与模式守卫装饰器。"""

import functools
import os

from pwn import ELF, process, remote

from ..core.env import call_CDLL_func
from ..core.log import (errlog_exit, get_callframe_info, log2_ex, log_code_base_addr,
                  log_ex, log_libc_base_addr, warn_ex)
from ..toolkit.onegadget import ldd_get_libc_path, one_gadget, one_gadget_binary
from ..toolkit.recv import get_segment_base_addr_by_proc_maps, recv_libc_addr
from ..core.state import gift

__all__ = [
    "only_debug", "only_gdb", "only_nogdb", "only_remote", "only_debug_or_remote",
    "stop", "S",
    "get_current_one_gadget_from_file", "get_current_one_gadget_from_libc",
    "get_current_codebase_addr", "get_current_libcbase_addr",
    "get_current_stackbase_addr", "get_current_heapbase_addr",
    "recv_current_libc_addr", "set_current_libc_base", "set_current_libc_base_and_log",
    "set_current_code_base", "set_current_code_base_and_log", "set_remote_libc",
    "copy_current_io", "call_current_CDLL_func",
    "switch_io", "s", "sl", "sa", "sla", "st", "slt", "ru", "rl", "rs",
    "rls", "rlc", "rle", "ra", "rr", "r", "rn", "ia", "ic", "cr",
]


def only_debug(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because debug mode is not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def only_gdb(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io and gift.gdb_obj:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because debug mode and gdb are not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def only_nogdb(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.debug and not gift.remote and gift.io and not gift.gdb_obj and not gift.gdb_pid:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because gdb is enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def only_remote(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if gift.remote and not gift.debug and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because remote mode is not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def only_debug_or_remote(show_warn=True):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
            if (gift.remote or gift.debug) and gift.io:
                res = func_call(*args, **kwargs)
            else:
                if show_warn:
                    warn_ex(
                        "'{}' will not be called because debug or remote mode is not enabled.".format(func_call.__name__))
                res = None
            return res
        return wrapper2
    return wrapper1


def stop(enable=True):
    """停止程序并打印调用者信息

    Args:
        enable (bool, optional): 为 False 时直接返回，默认为 True。
    """
    if not enable:
        return

    if gift.get('no_stop', None):
        return

    func_name = ''
    module_name = ''
    lineno, pid = -1, -1
    try:
        # 尝试获取文件行号
        module_name, func_name, lineno = get_callframe_info(depth=3)
    except:
        lineno = -1

    # 尝试获取 pid
    if gift.get('io', None) and gift.get('debug', None):
        pid = gift['io'].proc.pid

    msg = 'Stop'
    if lineno != -1:
        msg += ' at module: {}  function: {}  line: {}'.format(
            module_name, func_name, lineno)
    if pid != -1:
        msg += '  local pid: {}'.format(pid)
    log2_ex(msg)
    input("👉 Press any key to continue......")


S = stop


def get_current_one_gadget_from_file(libc_base=0, more=False):
    """获取当前文件名的所有 one_gadget。

    """
    if not gift.filename:
        errlog_exit("Cannot get_current_one_gadget, filename is None!")
    res = [x + libc_base for x in one_gadget_binary(gift['filename'], more)]
    log_ex("Get one_gadget: {} from {}".format(
        [hex(x) for x in res], ldd_get_libc_path(gift['filename'])))
    return res


def get_current_one_gadget_from_libc(more=False):
    """从当前 libc 获取所有 one_gadget

    """
    if not gift.libc:
        errlog_exit("Cannot get_current_one_gadget_from_libc, libc is None!")
    res = [
        x + gift['libc'].address for x in one_gadget(gift['libc'].path, more)]
    log_ex("Get one_gadget: {} from {}".format(
        [hex(x) for x in res], gift['libc'].path))
    return res


_cache_segment_base_addr = None


@only_debug()
def __get_current_segment_base_addr(use_cache=True) -> dict:
    global _cache_segment_base_addr
    """获取当前进程各段的基址。"""
    if use_cache and _cache_segment_base_addr is not None:
        return _cache_segment_base_addr

    pid = gift.io.proc.pid
    filename = gift.filename
    if filename is not None:
        filename = os.path.split(os.path.abspath(filename))[1]
    _cache_segment_base_addr = get_segment_base_addr_by_proc_maps(
        pid, filename)
    return _cache_segment_base_addr


def get_current_codebase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['code'] if r else 0


def get_current_libcbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['libc'] if r else 0


def get_current_stackbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['stack'] if r else 0


def get_current_heapbase_addr(use_cache=True) -> int:
    r = __get_current_segment_base_addr(use_cache)
    return r['heap'] if r else 0


def recv_current_libc_addr(offset: int = 0, timeout=5):
    if not gift.get("elf", None):
        errlog_exit("Can not get current libc addr because of no elf.")
    if not gift.get('io', None):
        errlog_exit("Can not get current libc addr because of no io.")

    return recv_libc_addr(gift['io'], bits=gift['elf'].bits, offset=offset, timeout=timeout)


def _innner_set_current_base(addr: int, offset: str or int, name: str) -> int:
    if addr is None:
        if name == "libc":
            addr = recv_current_libc_addr()
        else:
            raise RuntimeError("addr is None")

    if not gift[name]:
        errlog_exit("No {} here.".format(name))
    if gift[name].address != 0:
        errlog_exit("The address of current {} is not 0.".format(name))
    if isinstance(offset, str):
        offset = gift[name].sym[offset]

    base_addr = addr - offset
    gift[name].address = base_addr
    return base_addr


def set_current_libc_base(addr: int = None, offset: str or int = 0) -> int:
    """set_current_libc_base

    Args:
        addr (int): 获取到的地址。为 None 时使用 'recv_current_libc_addr' 获取地址。
        offset (str or int): 偏移或当前 libc 中的函数名

    Returns:
        int: libc 基址
    """
    return _innner_set_current_base(addr, offset, 'libc')


def set_current_libc_base_and_log(addr: int = None, offset: int or str = 0):
    """set_current_libc_base 并记录日志

    Args:
        addr (int): 获取到的地址。为 None 时使用 'recv_current_libc_addr' 获取地址。
        offset (str or int): 偏移或当前 libc 中的函数名。

    Returns:
        int: libc 基址
    """
    res = set_current_libc_base(addr, offset)
    log_libc_base_addr(res)
    return res


def set_current_code_base(addr: int, offset: str or int = 0) -> int:
    """set_current_code_base

    Args:
        addr (int): 获取到的地址。
        offset (str or int): 偏移或当前 elf 中的函数名

    Returns:
        int: elf 基址
    """
    return _innner_set_current_base(addr, offset, 'elf')


def set_current_code_base_and_log(addr: int, offset: int or str = 0):
    """set_current_code_base 并记录日志

    Args:
        addr (int): 获取到的地址。
        offset (str or int): 偏移或当前 elf 中的函数名

    Returns:
        int: elf 基址
    """
    res = set_current_code_base(addr, offset)
    log_code_base_addr(res)
    return res


@only_remote()
def set_remote_libc(libc_so_path: str) -> ELF:
    if os.path.exists(libc_so_path) and os.path.isfile(libc_so_path):
        gift['libc'] = ELF(libc_so_path, checksec=False)
        gift['libc'].address = 0
        return gift['libc']
    else:
        errlog_exit("libc_so_path not exists!")


@only_debug_or_remote()
def copy_current_io():
    """仅用于 debug/remote 命令"""
    io = None
    if gift.get('debug'):
        io = process(
            gift.process_args, timeout=gift.context_timeout, env=gift.process_env)

    elif gift.get('remote'):
        io = remote(gift.ip, gift.port, timeout=gift.context_timeout)
    else:
        raise RuntimeError("copy_current_io error, no debug and no remote!")
    return io


@only_debug()
def call_current_CDLL_func(func_name: str, *func_args):
    """call_current_CDLL_func("rand")

    Args:
        func_name (str): 函数名

    Returns:
        _type_: _description_
    """
    return call_CDLL_func(gift.libc.path if gift.libc  else None, func_name, *func_args)


def switch_io(io):
    """将 gift['io'] 切换到另一个 tube，使所有缩写函数（sla、ru 等）作用于它。"""
    gift['io'] = io


def s(*args, **kwargs):
    """发送"""
    io = gift.get("io", None)
    if io:
        io.send(*args, **kwargs)


def sl(*args, **kwargs):
    """发送一行"""
    io = gift.get("io", None)
    if io:
        io.sendline(*args, **kwargs)


def sa(*args, **kwargs):
    """接收到指定内容后发送"""
    io = gift.get("io", None)
    if io:
        io.sendafter(*args, **kwargs)


def sla(*args, **kwargs):
    """接收到指定内容后发送一行"""
    io = gift.get("io", None)
    if io:
        io.sendlineafter(*args, **kwargs)


def st(*args, **kwargs):
    """接收到指定内容后发送（满足即返回）"""
    io = gift.get("io", None)
    if io:
        io.sendthen(*args, **kwargs)


def slt(*args, **kwargs):
    """接收到指定内容后发送一行（满足即返回）"""
    io = gift.get("io", None)
    if io:
        io.sendlinethen(*args, **kwargs)


def ru(*args, **kwargs) -> bytes:
    """接收直到指定内容"""
    io = gift.get("io", None)
    if io:
        return io.recvuntil(*args, **kwargs)


def rl(*args, **kwargs) -> bytes:
    """接收一行"""
    io = gift.get("io", None)
    if io:
        return io.recvline(*args, **kwargs)


def rs(*args, **kwargs) -> list:
    """接收多行"""
    io = gift.get("io", None)
    if io:
        return io.recvlines(*args, **kwargs)


def rls(*args, **kwargs) -> bytes:
    """接收以指定内容开头的行"""
    io = gift.get("io", None)
    if io:
        return io.recvline_startswith(*args, **kwargs)


def rle(*args, **kwargs) -> bytes:
    """接收以指定内容结尾的行"""
    io = gift.get("io", None)
    if io:
        return io.recvline_endswith(*args, **kwargs)


def rlc(*args, **kwargs) -> bytes:
    """接收包含指定内容的行"""
    io = gift.get("io", None)
    if io:
        return io.recvline_contains(*args, **kwargs)


def ra(timeout=5) -> bytes:
    """接收全部"""
    io = gift.get("io", None)
    if io:
        return io.recvall(timeout)


def rr(*args, **kwargs) -> bytes:
    """按正则接收"""
    io = gift.get("io", None)
    if io:
        return io.recvregex(*args, **kwargs)


def r(*args, **kwargs) -> bytes:
    """接收"""
    io = gift.get("io", None)
    if io:
        return io.recv(*args, **kwargs)


def rn(*args, **kwargs) -> bytes:
    """接收指定字节数"""
    io = gift.get("io", None)
    if io:
        return io.recvn(*args, **kwargs)


def ia():
    """进入交互"""
    io = gift.get("io", None)
    if io:
        io.interactive()


def ic():
    """关闭"""
    io = gift.get("io", None)
    if io:
        io.close()


def cr(timeout=0) -> bool:
    """是否可接收"""
    io = gift.get("io", None)
    if io:
        return io.can_recv(timeout)
