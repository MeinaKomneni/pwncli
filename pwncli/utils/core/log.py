"""日志输出、地址打印，以及为日志服务的栈帧内省。"""

import os
import sys

import click

__all__ = [
    # 多个日志函数
    "log_ex",
    "log_ex_highlight",
    "log2_ex",
    "log2_ex_highlight",
    "warn_ex",
    "warn_ex_highlight",
    "errlog_ex",
    "errlog_ex_highlight",
    "errlog_exit",
    "errlog_ex_highlight_exit",
    "log_address",
    "leak",
    "log_address_ex",
    "leak_ex",
    "log_address_ex2",
    "leak_ex2",
    "log_libc_base_addr",
    "log_heap_base_addr",
    "log_code_base_addr",
    # 栈帧内省
    "get_func_signature_str",
    "get_callframe_info",
]


def get_func_signature_str(func_name: str, *args, **kwargs):
    args_str = ""
    kwargs_str = ""
    if args:
        args_str = ", ".join(str(x) for x in args)
    if kwargs:
        if args_str:
            args_str += ", "
        kwargs_str = ", ".join("{}={}".format(_k, _v) for _k, _v in kwargs.items())
    return "{}({}{})".format(func_name, args_str, kwargs_str)


def get_callframe_info(depth:int=2):
    """获取栈帧信息

    Args:
        depth (int, optional): 栈帧深度，默认为 2

    Raises:
        OSError: 若 depth < 1 则抛出 OSError

    Returns:
        tuple: module_name, func_name, lineno
    """
    if depth < 1:
        raise OSError("depth must be bigger than 1")
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    module_name = os.path.split(bf.f_code.co_filename)[1]
    func_name = bf.f_code.co_name
    lineno = bf.f_lineno
    return module_name, func_name, lineno


def log_ex(msg, *args):
    """向标准输出记录一条消息。"""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("INFO", fg="green"), msg))


def log_ex_highlight(msg, *args):
    """向标准输出记录一条消息。"""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("INFO", fg="green", bg="white"), msg))


def log2_ex(msg, *args):
    """向标准输出记录一条重要消息。"""
    if args:
        msg %= args
    click.echo("[#] {}  {}".format(click.style("IMPORTANT INFO", fg="blue"), msg))


def log2_ex_highlight(msg, *args):
    """向标准输出记录一条消息。"""
    if args:
        msg %= args
    click.echo("[#] {}  {}".format(click.style("IMPORTANT INFO", fg="blue", bg="white"), msg))

def warn_ex(msg, *args):
    """向标准输出记录一条告警消息。"""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("WARN", fg="yellow"), msg))


def warn_ex_highlight(msg, *args):
    """向标准输出记录一条告警消息。"""
    if args:
        msg %= args
    click.echo("[*] {}  {}".format(click.style("WARN", fg="yellow", bg="white"), msg))


def errlog_ex(msg, *args):
    """向标准错误记录一条消息。"""
    if args:
        msg %= args
    click.echo("[!] {}  {}".format(click.style("ERROR", fg="red"), msg))


def errlog_ex_highlight(msg, *args):
    """向标准输出记录一条消息。"""
    if args:
        msg %= args
    click.echo("[!] {}  {}".format(click.style("ERROR", fg="red", bg="white"), msg))


def errlog_exit(msg, *args):
    """向标准错误记录一条消息后退出。"""
    errlog_ex(msg, *args)
    exit(-1)


def errlog_ex_highlight_exit(msg, *args):
    """向标准错误记录一条消息后退出。"""
    errlog_ex_highlight(msg, *args)
    exit(-1)


def log_address(desc:str, address:int):
    """以十六进制格式打印地址

    Args:
        desc (str): 地址的描述
        address (int): 地址
    """
    log_ex("{} ===> {}".format(desc, hex(address)))

leak = log_address

def log_address_ex(variable_name:str, depth=2):
    """借助栈帧，根据变量名记录其地址。

    Args:
        variable_name (str): 变量名。
        depth (int, optional): 栈帧深度，默认为 2。
    """
    assert isinstance(variable_name, str), "variable_name must be a string!"
    assert depth >= 2, "depth error!"
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    loc_var = bf.f_locals
    if variable_name not in loc_var:
        errlog_ex("Cannot find {}! Maybe the depth is wrong!".format(variable_name))
    else:
        var = loc_var[variable_name]
        assert isinstance(var, int), "The address is not int!"
        log_address(variable_name, var)

leak_ex = log_address_ex

def log_address_ex2(variable: int, depth: int=2):
    """根据变量记录地址

    Args:
        variable (int): 要记录的变量，必须为 int。
        depth (int, optional): 栈帧深度，默认为 2。
    """
    assert isinstance(variable, int), "variable's type must be int!"
    assert depth >= 2, "depth error!"
    bf = sys._getframe()
    for i in range(depth - 1):
        bf = bf.f_back
    loc_var = bf.f_locals

    for k, v in loc_var.items():
        if isinstance(v, int) and v == variable:
            log_address(k, variable)
            return
    errlog_exit("Cannot find variable, check your depth!")

leak_ex2 = log_address_ex2

def log_libc_base_addr(address:int):
    log_address("libc_base_addr", address)


def log_heap_base_addr(address:int):
    log_address("heap_base_addr", address)


def log_code_base_addr(address:int):
    log_address("code_base_addr", address)
