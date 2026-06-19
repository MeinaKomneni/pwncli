"""运行环境探测（tmux / wsl / gdb 插件 / ELF 架构）与底层 ctypes、signal 调用。"""

import ctypes
import os
import signal

from pwn import ELF, which

__all__ = [
    "call_CDLL_func",
    "TimeoutPwncli",
]


def call_CDLL_func(dll_path: str, func_name: str, *func_args):
    """调用 cdll 函数

    call_CDLL_func("", "rand")

    Args:
        dll_path (str): 若 dll_path 为空，则使用 /lib/x86_64-linux-gnu/libc.so.6
        func_name (str): 函数名

    Returns:
        _type_: 调用结果
    """
    if not dll_path:
        dll_path = "/lib/x86_64-linux-gnu/libc.so.6"
    dll = ctypes.cdll.LoadLibrary(dll_path)
    func = getattr(dll, func_name)
    return func(*func_args)


class TimeoutPwncli:
    """with TimeoutPwncli(seconds=1): whiel True: print(1)
    """

    def __init__(self, seconds=5, timeout_msg="Timeout!", handle_func=None, *handle_func_args):
        self._seconds = seconds
        self._timeout_msg = timeout_msg
        self._handle_func = handle_func
        self._handle_func_args = handle_func_args

    def handle_timeout(self, signum, frame):
        if self._handle_func:
            self._handle_func(*self._handle_func_args)
        else:
            raise TimeoutError(self._timeout_msg)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self._seconds)


    def __exit__(self, type, value, traceback):
        signal.alarm(0)


def _get_elf_arch_info(filename):
    _e = ELF(filename, checksec=False)
    arch = _e.arch
    del _e
    return arch

def _in_tmux():
    return bool('TMUX' in os.environ and which('tmux'))

def _in_wsl():
    if os.path.exists('/proc/sys/kernel/osrelease'):
        with open('/proc/sys/kernel/osrelease', 'rb') as f:
            is_in_wsl = b'icrosoft' in f.read()
        if is_in_wsl and which('wsl.exe') and which("cmd.exe"):
            return True
    return False

def _get_gdb_plugin_info():
    with open(os.path.expanduser("~/.gdbinit"), "a+", encoding="utf-8") as f:
        f.seek(0, 0)
        for line in f:
            if line.strip().startswith("source"):
                if "pwndbg" in line:
                    return "pwndbg"
                elif "gef" in line:
                    return "gef"
                elif "peda" in line:
                    return "peda"
    return None
