#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""操作当前调试会话的 gdb —— 启动/附加、heaptrace、运行时查询与控制。"""

import os
import re
import subprocess
import time

from pwn import atexit, attach, process, remote, sleep, wget, which

from .current_session import only_gdb, only_nogdb, stop
from ..core.env import _in_tmux, _in_wsl
from .gdb_helper import *
from .gdb_helper import _get_tmux_info
from ..core.log import errlog_exit, log_ex, warn_ex
from ..core.state import gift

__all__ = [
    "launch_current_gdb", "attach_existing_process", "kill_current_gdb",
    "send_signal2current_gdbprocess", "send_continue2current_gdbprocess",
    "execute_cmd_in_current_gdb", "set_current_pie_breakpoints",
    "tele_current_pie_content", "add_struct2current_gdb_by_member",
    "add_struct2current_gdb_by_file", "add_show_struct_command2current_gdb",
    "kill_heaptrace", "launch_heaptrace",
    "gdb_cmd", "gdb_top_chunk_addr", "gdb_heap_base", "gdb_bins", "gdb_heap",
]


_tmux_pane = None


_gnome_pid = -1


_heaptrace_pid = -100


def _kill_heaptrace_in_tmux_pane():
    global _tmux_pane, _heaptrace_pid
    os.system("tmux send-keys -t {} C-c 2>/dev/null".format(_tmux_pane))
    os.system("tmux kill-pane -t {} 2>/dev/null".format(_tmux_pane))


def _kill_heaptrace_in_gnome():
    # global _gnome_pid, _heaptrace_pid
    # os.system("kill -SIGINT {} 2>/dev/null".format(_heaptrace_pid))
    # os.system("kill -9 {} 2>/dev/null".format(_gnome_pid))
    pass


def _kill_heaptrace_in_wsl():
    # global _heaptrace_pid
    # os.system("kill -SIGINT {} 2>/dev/null".format(_heaptrace_pid))
    pass


def _launch_heaptrace_in_tmux(sym_cmd):
    global _tmux_pane, _heaptrace_pid
    log_ex("Launch heaptrace in tmux...")
    pid = gift.io.pid
    _tmux_pane = subprocess.check_output(
        ["tmux", "splitw", "-h", '-F#{session_name}:#{window_index}.#{pane_index}', "-P"]).decode().strip()
    atexit.register(_kill_heaptrace_in_tmux_pane)
    os.system(
        "tmux send-keys -t {} 'heaptrace --attach {} {}' C-m".format(_tmux_pane, pid, sym_cmd))
    os.system("tmux select-pane -L")


def _launch_heaptrace_in_wsl(sym_cmd):
    log_ex("Launch heaptrace in wsl...")
    global _heaptrace_pid
    pid = gift.io.pid
    cmd = "cmd.exe /c start wt.exe wsl.exe -d {} bash -c \"{}\"".format(
        os.getenv("WSL_DISTRO_NAME"), "heaptrace --attach {} {}".format(pid, sym_cmd))
    os.system(cmd)


def _launch_heaptrace_in_gnome(sym_cmd):
    global _gnome_pid, _heaptrace_pid
    log_ex("Launch heaptrace in gnome...")
    pid = gift.io.pid
    p = subprocess.Popen(["gnome-terminal", "--", "sh", "-c",
                         "heaptrace --attach {} {}".format(pid, sym_cmd)])
    global _gnome_pid
    _gnome_pid = p.pid
    atexit.register(_kill_heaptrace_in_gnome)


@only_nogdb()
def kill_heaptrace():
    if _in_tmux():
        _kill_heaptrace_in_tmux_pane()
    elif _in_wsl():
        _kill_heaptrace_in_wsl()
    elif which("gnome-terminal"):
        _kill_heaptrace_in_gnome()


@only_nogdb()
def launch_heaptrace(stop_=True, malloc_off='', free_off='', realloc_off=''):
    if not which("heaptrace"):
        res = input(
            "Install heaptrace from https://github.com/Arinerron/heaptrace/releases/download/2.2.8/heaptrace? [y/n]").strip()
        if res != "y":
            errlog_exit("Cannot find heaptrace!")
        try:
            wget("https://github.com/Arinerron/heaptrace/releases/download/2.2.8/heaptrace",
                 save=True, timeout=300)
            subprocess.check_output(["chmod", "+x", "heaptrace"])
            bin_path = "$HOME/.local/bin" if os.getuid() != 0 else "/usr/local/bin"
            subprocess.check_output(["mv", "heaptrace", bin_path])
        except:
            errlog_exit("Cannot download or install heaptrace!")

    if not malloc_off:
        prefix = "libc+"
        if "malloc" in gift.elf.sym:
            prefix = "bin+"
        malloc_off = prefix+hex(gift.libc.sym.malloc - gift.libc.address)

    if not free_off:
        prefix = "libc+"
        if "free" in gift.elf.sym:
            prefix = "bin+"
        free_off = prefix+hex(gift.libc.sym.free - gift.libc.address)

    if not realloc_off:
        prefix = "libc+"
        if "realloc" in gift.elf.sym:
            prefix = "bin+"
        realloc_off = prefix+hex(gift.libc.sym.realloc - gift.libc.address)

    sym_cmd = "--symbols \"malloc={},free={},realloc={}\"".format(
        malloc_off, free_off, realloc_off)

    if _in_tmux():
        _launch_heaptrace_in_tmux(sym_cmd)
    elif _in_wsl() and which("wt.exe"):
        _launch_heaptrace_in_wsl(sym_cmd)
        sleep(1)
    elif which("gnome-terminal"):
        _launch_heaptrace_in_gnome(sym_cmd)
    else:
        errlog_exit("Don't know how to launch heaptrace!")
    stop(stop_)


@only_nogdb()
def launch_current_gdb(gdbscript: str, stop_=True):
    attach(gift.io, gdbscript=gdbscript)
    stop(stop_)


def _pids_by_process_name(name: str) -> list:
    """将进程名解析为 pid 列表，按 pid 升序排列。

    使用 `pgrep -x` 对进程名（comm 字段，内核截断为 15 字符）做精确匹配。
    刻意不匹配完整命令行：那会附加到仅在其参数中提到该名的无关进程上。
    """
    try:
        out = subprocess.check_output(["pgrep", "-x", name], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        out = b""
    except FileNotFoundError:
        errlog_exit("'pgrep' not found, cannot resolve process name '{}'.".format(name))
    return sorted(int(x) for x in out.split())


def attach_existing_process(target, gdbscript: str = "", stop_=True):
    """通过 pid 或进程名，将 gdb 附加到一个已在运行的进程上。

    与 `launch_current_gdb` 不同，此函数不要求 pwncli 的 debug 模式，
    可作用于任意已存在的进程。

    Args:
        target (int | str): 待附加的 pid（int）或进程名（str）。
            当名称匹配到多个进程时，给出告警并选择 pid 最小的一个。
        gdbscript (str): 附加后立即执行的 gdb 命令。
        stop_ (bool): 附加后是否暂停脚本，默认为 True。

    Returns:
        pwntools `attach` 返回的 gdb 实例，失败时为 None。
    """
    if isinstance(target, str) and target.strip().isdigit():
        target = int(target.strip())

    if isinstance(target, int):
        pid = target
    elif isinstance(target, str):
        pids = _pids_by_process_name(target)
        if not pids:
            errlog_exit("No running process named '{}' found.".format(target))
        if len(pids) > 1:
            warn_ex("Multiple processes named '{}' found: {}. Attaching to the first one: {}.".format(
                target, pids, pids[0]))
        pid = pids[0]
    else:
        errlog_exit("attach_existing_process: 'target' must be a pid (int) or a process name (str), got {}.".format(
            type(target).__name__))

    if not os.path.exists("/proc/{}".format(pid)):
        errlog_exit("Process with pid {} does not exist.".format(pid))

    log_ex("Attaching gdb to existing process, pid: {}".format(pid))
    res = attach(pid, gdbscript=gdbscript)
    stop(stop_)
    return res


def gdb_cmd(cmd: str, wait: float = 0.5, timeout: float = 10.0,
            quiet: bool = False, capture_lines: int = 0) -> str:
    """向运行在 tmux 中的 gdb 发送命令并返回其输出。

    与 execute_cmd_in_current_gdb（即发即忘）不同，此函数会捕获并返回 gdb 的输出，
    便于在利用过程中查看堆、内存或寄存器。

    Args:
        cmd: gdb 命令（如 "heap"、"x/40gx 0x555..."、"bins"）。
        wait: 每次轮询 gdb 输出完成时等待的秒数。
        timeout: 等待 gdb 回到 prompt 的最长秒数。
        quiet: 为 True 时不打印输出。
        capture_lines: 大于 0 时捕获指定行数的回滚历史（用于 `heap` 之类的长输出）。
            设置后会先清空 pane 的回滚历史，仅捕获本次命令的输出。
            注意：这会作为副作用清空 pane 的回滚历史。

    Returns:
        捕获到的 gdb 输出字符串。失败或被禁用（如远程模式、不在 tmux 中）时返回空字符串。
    """
    # remote 模式下没有附加在目标上的本地 gdb,直接禁用
    if gift.get('remote'):
        warn_ex("gdb_cmd: disabled in remote mode (no local gdb on the target).")
        return ""

    pane = _get_tmux_info()
    if not pane:
        warn_ex("gdb_cmd: not in tmux, cannot send command to gdb.")
        return ""

    _prompt_markers = ('pwndbg>', 'gef>', 'gdb>', '(gdb)')

    def _capture(history=0):
        args = ["tmux", "capture-pane", "-t", pane, "-p"]
        if history:
            args += ["-S", str(-history)]
        try:
            return subprocess.check_output(args).decode(errors='replace')
        except subprocess.CalledProcessError:
            return ""

    def _has_prompt(text):
        for line in reversed(text.strip().splitlines()):
            stripped = line.strip()
            if stripped:
                return any(stripped.startswith(m) or stripped.endswith(m) for m in _prompt_markers)
        return False

    def _wait_for_prompt(history=0):
        elapsed = 0.0
        while elapsed < timeout:
            time.sleep(wait)
            elapsed += wait
            snap = _capture(history) if history else _capture()
            if _has_prompt(snap):
                return snap
        return _capture(history) if history else _capture()

    # 反复发 Ctrl-C 直到 gdb 回到 prompt(已在 prompt 时 C-c 无影响)
    elapsed = 0.0
    while elapsed < timeout:
        snap = _capture()
        if _has_prompt(snap):
            break
        os.system("tmux send-keys -t {} C-c".format(pane))
        time.sleep(wait)
        elapsed += wait

    # Ctrl-L 清屏,让 pane 只剩 prompt(C-l 会把可见区推入 scrollback)
    os.system("tmux send-keys -t {} C-l".format(pane))
    time.sleep(0.1)
    # 需要抓长输出时,在 C-l 之后再清 scrollback:否则 C-l 推入的旧内容(可能含
    # 上一次同命令的回显)会留在 scrollback 里,导致 -S -N 捕获时第一个回显命中旧的
    if capture_lines:
        os.system("tmux clear-history -t {}".format(pane))

    # 发送命令
    escaped = cmd.replace("\\", "\\\\").replace("'", "'\\''")
    os.system("tmux send-keys -t {} '{}' Enter".format(pane, escaped))

    # 等命令执行完(prompt 再次出现)
    time.sleep(0.2)
    raw = _wait_for_prompt(capture_lines) if capture_lines else _wait_for_prompt()

    # 解析:定位命令回显行(pwndbg> <cmd>),丢弃到该行(含),取其后内容
    # 这样即便 capture -S 抓到了 C-l 推入 scrollback 的旧内容,也会被回显行隔开丢掉
    result_lines = raw.splitlines()
    cmd_head = cmd.strip()

    def _strip_prompt_prefix(s):
        for m in _prompt_markers:
            if s.startswith(m):
                return s[len(m):].strip()
        return s.strip()

    echo_idx = -1
    for i, line in enumerate(result_lines):
        if _strip_prompt_prefix(line).startswith(cmd_head):
            echo_idx = i
            break
    if echo_idx >= 0:
        result_lines = result_lines[echo_idx + 1:]

    # 去掉末尾的空行/prompt 行
    while result_lines:
        line = result_lines[-1].strip()
        if not line or any(line.startswith(m) or line.endswith(m) for m in _prompt_markers):
            result_lines.pop()
        else:
            break
    result = '\n'.join(result_lines).strip()
    if result and not quiet:
        print(result)
    return result


def _parse_hex_int(text: str) -> int:
    """从 gdb 输出中提取首个 0x.. 整数，无则返回 0。"""
    if not text:
        return 0
    m = re.search(r'0x[0-9a-fA-F]+', text)
    return int(m.group(), 16) if m else 0


def gdb_top_chunk_addr() -> int:
    """返回 main arena 的 top chunk 地址（需要 pwndbg）。

    使用 pwndbg 的 heap Python API，结果是干净的整数而非解析表格。
    堆未初始化或缺少 pwndbg 时返回 0。
    """
    out = gdb_cmd("py print(hex(pwndbg.aglib.heap.current.main_arena.top))",
                  quiet=True)
    addr = _parse_hex_int(out)
    if addr:
        log_ex("top chunk addr: {}".format(hex(addr)))
    return addr


def gdb_heap_base() -> int:
    """返回 main arena 的堆基址（需要 pwndbg）。

    返回 main arena 的 top chunk 所在堆区域的起始地址。不可用时返回 0。
    """
    out = gdb_cmd(
        "py print(hex(pwndbg.aglib.heap.current.main_arena.active_heap.start))",
        quiet=True)
    addr = _parse_hex_int(out)
    if addr:
        log_ex("heap base: {}".format(hex(addr)))
    return addr


def gdb_bins(timeout: float = 15.0) -> str:
    """执行 pwndbg 的 `bins` 并返回其输出（tcache + 全部 bin 列表）。"""
    return gdb_cmd("bins", timeout=timeout, capture_lines=400)


def gdb_heap(timeout: float = 20.0) -> str:
    """执行 pwndbg 的 `heap` 并返回其输出（完整 chunk 列表）。

    最多捕获 1000 行回滚历史；过大的堆仍可能被截断。
    """
    return gdb_cmd("heap", timeout=timeout, capture_lines=1000)


@only_gdb()
def kill_current_gdb():
    """杀掉当前 gdb 进程。"""
    try:
        kill_gdb(gift['gdb_obj'])
    except:
        kill_gdb(gift['gdb_pid'])


@only_gdb()
def send_signal2current_gdbprocess(sig_val: int = 2):
    sleep(0.2)
    if _in_tmux():
        os.system("tmux send-keys -t {} C-c 2>/dev/null".format(_get_tmux_info()))
    else:
        os.system("kill -{} {}".format(sig_val, gift['gdb_pid']))
    time.sleep(0.2)


@only_gdb()
def send_continue2current_gdbprocess():
    execute_cmd_in_gdb(gift["gdb_obj"], "continue")


@only_gdb()
def execute_cmd_in_current_gdb(cmd: str):
    """在当前 gdb 中执行命令，按 ';' 或 \\n 分割命令。"""
    execute_cmd_in_gdb(gift["gdb_obj"], cmd)


@only_gdb()
def set_current_pie_breakpoints(offset: int):
    """当二进制开启 PIE 时按偏移设置断点。仅支持 `pwndbg`。"""
    set_pie_breakpoints(gift["gdb_obj"], offset)


@only_gdb()
def tele_current_pie_content(offset: int, number=10):
    """当二进制开启 PIE 时按偏移 telescope 当前内容。仅支持 'pwndbg'。"""
    tele_pie_content(gift["gdb_obj"], offset, number)


@only_gdb()
def add_struct2current_gdb_by_member(struct_name, add_show_cmd=False, *struct_mems, **struct_memskw):
    add_struct_by_member(gift["gdb_obj"], struct_name,
                         add_show_cmd, *struct_mems, **struct_memskw)


@only_gdb()
def add_struct2current_gdb_by_file(file_content, add_show_cmd=False, *struct_names):
    add_struct_by_file(gift["gdb_obj"], file_content,
                       add_show_cmd, *struct_names)


@only_gdb()
def add_show_struct_command2current_gdb(*struct_names):
    add_show_struct_command(gift["gdb_obj"], *struct_names)
