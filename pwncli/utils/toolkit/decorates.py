#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : decorates.py
@Time    : 2021/11/23 23:48:12
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : Decorators
'''


import functools
import os
import signal
import sys
import time
from enum import Enum, unique

from pwn import ELF, process, remote, tube

try:
    from collections.abc import Iterable
except:
    from collections import Iterable

from inspect import signature
from itertools import product
from typing import Callable, List

from ..core.exceptions import PwncliExit
from ..core.log import (errlog_exit, get_func_signature_str, log_ex,
                  warn_ex_highlight)
from .onegadget import ldd_get_libc_path

__all__  = [
    'timer', 
    'sleep_call_before', 
    "sleep_call_after", 
    "sleep_call_all", 
    "sleeper",
    "bomber",
    "deprecated", 
    "unused",
    "show_name",
    "always_success",
    "limit_calls",
    "retry",
    "add_prompt",
    "cache_result",
    "cache_nonresult",
    "signature2name",
    "call_multimes",
    "count_calls",
    "convert_str2bytes",
    "convert_bytes2str"
    ]

# 将 bytes 类型的参数转换为 str
def convert_bytes2str(func):
    """装饰器。

    将 bytes 类型的参数转换为 str"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        new_args = []
        for a in args:
            if isinstance(a, bytes):
                new_args.append(a.decode('latin-1'))
            else:
                new_args.append(a)
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, bytes):
                new_kwargs[k] = v.decode('latin-1')
            else:
                new_kwargs[k] = v
        return func(*new_args, **new_kwargs)
    return wrapper

# 将 str 类型的参数转换为 bytes
def convert_str2bytes(func):
    """装饰器。

    将 str 类型的参数转换为 bytes"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        new_args = []
        for a in args:
            if isinstance(a, str):
                new_args.append(a.encode('latin-1'))
            else:
                new_args.append(a)
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, str):
                new_kwargs[k] = v.encode('latin-1')
            else:
                new_kwargs[k] = v
        return func(*new_args, **new_kwargs)
    return wrapper


def count_calls(show=True):
    """装饰器。

    统计函数被调用的次数。

    通过 func._num_calls 获取调用次数。

    Args:
        show (bool, optional): 是否显示调用次数，默认为 True。
    """
    def _wrapper(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            wrapper._num_calls += 1
            if show:
                print("Call {} of {}".format(wrapper._num_calls, func.__name__))
            return func(*args, **kwargs)
        wrapper._num_calls = 0
        return wrapper
    return _wrapper


def signature2name(func):
    """装饰器。

    将函数的签名作为其名称"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        wrapper.__name__ = sig
        return func(*args, **kwargs)
    return wrapper


def add_prompt(msg: str):
    """装饰器。

    在调用函数前打印消息。

    Args:
        msg (str): 输出到标准提示的消息
    """
    def wrapper1(func):
        
        @functools.wraps(func)
        @signature2name
        def wrapper2(*args, **kwargs):
            sig = get_func_signature_str(func.__name__, *args, **kwargs)
            log_ex("[call {}] prompt info --> {}".format(sig, msg))
            res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def always_success(show_err=True):
    """装饰器。

    调用函数时捕获异常。

    注意：无法处理 sys.exit。

    Args:
        show_err (bool, optional): 是否显示错误信息，默认为 False。
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            res = None
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                if show_err:
                    warn_ex_highlight("error info: {}".format(e))
            return res
        return wrapper2
    return wrapper1


def deprecated(msg: str=""):
    """装饰器。

    将函数标记为已弃用并显示消息。

    Args:
        msg (str, optional): 要显示的消息，默认为 ""。
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is deprecated. {}".format(func.__name__, msg))
            res = func(*args, **kwargs)
            return res
        return wrapper2
    return wrapper1


def unused(msg: str=""):
    """装饰器。

    将函数标记为未使用并显示消息。

    Args:
        msg (str, optional): 要显示的消息，默认为 ""。
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            warn_ex_highlight("This function: {} is unused and it would be removed in later version. {}".format(func.__name__, msg))
            return None
        return wrapper2
    return wrapper1


def limit_calls(times: int=1, warn_=True):
    """装饰器。

    限制函数的调用次数。

    Args:
        times (int, optional): 次数，默认为 1。
        warn_ (bool, optional): 是否显示告警信息，默认为 True。

    """
    _tmp = 0
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            nonlocal _tmp
            if _tmp < times:
                res = func(*args, **kwargs)
                _tmp += 1
            else:
                res = None
                if warn_:
                    warn_ex_highlight("This function {} has beed called for {} times, so it cannot be called any more.".format(func.__name__, times))
            return res
        return wrapper2
    return wrapper1

def call_multimes(times: int=1, ignore_err=False):
    """装饰器。

    循环调用函数指定次数。

    Args:
        times (int, optional): 次数，默认为 1。
    """

    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            res = None
            for _ in range(times):
                if not ignore_err:
                    res = func(*args, **kwargs)
                else:
                    try:
                        res = func(*args, **kwargs)
                    except:
                        res = None
            return res
        return wrapper2
    return wrapper1

def retry(times: int=1):
    """装饰器。

    发生错误时重试调用函数。

    Args:
        times (int, optional): 次数，默认为 1。
    """

    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            res = None
            for _ in range(times):
                try:
                    return func(*args, **kwargs)
                except:
                    pass
            return res
        return wrapper2
    return wrapper1

def cache_result(func: Callable):
    """装饰器。

    缓存函数的返回值。

    即首次返回值会在函数再次被调用时直接返回。
    """
    _res = None
    _flag = 0xdeadbeef
    @functools.wraps(func)
    def wrapper2(*args, **kwargs):
        nonlocal _flag, _res
        if _flag:
            _res = func(*args, **kwargs)
            _flag = 0
        return _res
    return wrapper2


def cache_nonresult(func: Callable):
    """装饰器。

    仅缓存非 None 的结果。

    一旦函数返回首个非 None 值，此后所有调用都将返回该缓存值。

    """
    _res = None
    _flag = 0xdeadbeef
    @functools.wraps(func)
    def wrapper2(*args, **kwargs):
        nonlocal _flag, _res
        if _flag:
            _res = func(*args, **kwargs)
            if _res is not None:
                _flag = 0
        return _res
    return wrapper2


def show_name(func: Callable):
    """装饰器。

    适用于模糊测试。

    调用函数时显示函数名。
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        log_ex("call {}".format(sig))
        res = func(*args, **kwargs)
        return res
    return wrapper


def timer(func):
    """装饰器。

    统计函数的耗时。

    Args:
        func ([type]): 函数

    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        sig = get_func_signature_str(func.__name__, *args, **kwargs)
        print('call {} execute time: {} s({} min)'.format(sig, end - start, (end - start) / 60))
        return res
    return wrapper


def bomber(seconds: int, callback=None):
    """装饰器。

    若函数在指定时间内未运行结束，则程序退出并抛出 TimeoutError。

    Args:
        seconds (int): 超时后抛出 TimeoutError 的秒数
        callback (Callable, optional): 超时时的回调，若 callback 不为 None，则返回 callback 的返回值，默认为 None。
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            def handler(n, f):
                raise TimeoutError()
            sig = get_func_signature_str(func.__name__, *args, **kwargs)
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                res = func(*args, **kwargs)
                signal.alarm(0)
            except TimeoutError:
                warn_ex_highlight("call %s Timeout!", sig)
                res = None
                if callback:
                    res = callback()
                else:
                    sys.exit(2)
            return res
        return wrapper2
    return wrapper1

@unique
class _SleepMode(Enum):
    BEFORE = 1
    AFTER = 2
    ALL = 3


def _sleep_call(second: int, mod: _SleepMode):
    """在调用函数前后休眠。

    Args:
        second (int, optional): 休眠时间，默认为 1。
        mod (_SleepMode, optional): 休眠模式，默认为 _SleepMode.BEFORE。
    """
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            if mod.value & 1:
                time.sleep(second)
            res = func(*args, **kwargs)
            if mod.value & 2:
                time.sleep(second)
            return res

        return wrapper2

    return wrapper1


sleep_call_before = functools.partial(_sleep_call, mod=_SleepMode.BEFORE)

sleep_call_after = functools.partial(_sleep_call, mod=_SleepMode.AFTER)

sleep_call_all = functools.partial(_sleep_call, mod=_SleepMode.ALL)

sleeper = sleep_call_after


@unique
class _EnumerateAttackMode(Enum):
    LOCAL=0
    REMOTE=1


def _call_func_invoke(call_func, libc_path, loop_time, loop_list, tube_func, *tube_args):
    libc = ELF(libc_path)
    # 调试输出 tube_args
    if loop_list:
        l_count = 0
        for iter_items in product(*loop_list):
            l_count += 1
            t = tube_func(*tube_args)
            libc.address = 0
            log_ex("[{}] ===> call func: {}, tube-args: {}, loop-args: {}".format(l_count, call_func.__name__, tube_args, iter_items))
            try:
                call_func(t, libc, *iter_items)
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
            except:
                pass
            finally:
                try:
                    t.close()
                except:
                    pass
    else:
        for i in range(loop_time):
            t = tube_func(*tube_args)
            libc.address = 0
            log_ex("[{}] ===> call func: {}, tube-args: {}".format(i+1, call_func.__name__, tube_args))
            try:
                call_func(t, libc)
            except PwncliExit as ex:
                log_ex("Pwncli is exiting...ex info: {}".format(ex))
                break
            except KeyboardInterrupt:
                errlog_exit("KeyboardInterrupt!")
                pass
            except:
                pass
            finally:
                try:
                    t.close()
                except:
                    pass


def _attack_local(argv, libc_path, call_func, loop_time, loop_list):
    # 参数检查
    if argv is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! argv:{} libc_path:{} loop_time: {} call_func: {}".format(argv, libc_path, loop_time, call_func.__name__))
    _call_func_invoke(call_func, libc_path, loop_time, loop_list, process, argv)


def _attack_remote(libc_path, ip, port, call_func, loop_time, loop_list):
    if ip is None or port is None or (not os.path.isfile(libc_path)) or loop_time <= 0 or call_func is None:
        raise RuntimeError("Para error! is:{} port: {} libc_path:{} loop_time: {} call_func: {}".format(ip, port, libc_path, loop_time, call_func.__name__))
    _call_func_invoke(call_func, libc_path, loop_time, loop_list, remote, ip, port)


def _check_func_args(func_call, loop_list, check_first):
    assert func_call is not None and callable(func_call), "func_call {} error!".format(func_call)
    # 检查函数参数
    sig = signature(func_call)
    pars = sig.parameters
    com_help_info = "\n\t\t\tThe first para must be 'tube' type, the second one must be 'ELF' type for libc! If loop_list is specified, every element is a list or tuple."
    # 若指定了 loop_list，函数参数个数必须为 2 + len(loop_list[0])
    if loop_list:
        assert isinstance(loop_list, (Iterable, list, tuple)), "  Loop_list is not tuple or list.\n"+com_help_info
        assert len(loop_list) > 0, "  Length of loop_list is 0.\n"+com_help_info
        for ll in loop_list:
            assert isinstance(ll, (Iterable, tuple, list)), "  An element of loop_list is not tuple or list.\n"+com_help_info
            assert len(ll) > 0, "  Length of an element of loop_list is 0.\n"+com_help_info
        # 检查参数个数
        if check_first:
            assert len(pars) == (2 + len(loop_list)), "  Length of para is not {}.\n".format(2 + len(loop_list))+com_help_info
    else:
        if check_first:
            assert len(pars) == 2, "  Length of para is not 2.\n"+com_help_info

    if check_first:
        kl = []
        vl = []
        for k, v in pars.items():
            kl.append(k)
            vl.append(v)

        assert (issubclass(vl[0].annotation, tube)) and (issubclass(vl[1].annotation, ELF)), "  Type of {} is: {}, type of {} is {}.".format(kl[0],
            vl[0].annotation, kl[1], vl[1].annotation)+com_help_info


def _light_enumerate_attack(argv, ip, port, attack_mode, libc_path=None, loop_time=0x10, loop_list:List[List]=None):
    def wrapper1(func_call):
        @functools.wraps(func_call)
        def wrapper2(*args, **kwargs):
                # 参数检查
                _check_func_args(func_call, loop_list, True)
                io, _ = args
                io.close()
                # 自动探测 libc_path
                if argv is not None and libc_path is None:
                    _libc_path = ldd_get_libc_path(argv)
                else:
                    _libc_path = libc_path
                # 本地进程或远程连接
                if attack_mode == _EnumerateAttackMode.LOCAL:
                    _attack_local(argv, _libc_path, func_call, loop_time, loop_list)
                elif attack_mode == _EnumerateAttackMode.REMOTE:
                    _attack_remote(_libc_path, ip, port, func_call, loop_time, loop_list)
        return wrapper2
    return wrapper1


local_enumerate_attack = functools.partial(_light_enumerate_attack, ip=None, port=None, attack_mode=_EnumerateAttackMode.LOCAL)

remote_enumerate_attack = functools.partial(_light_enumerate_attack, argv=None, attack_mode=_EnumerateAttackMode.REMOTE)

"""
例如，若使用 'local_enumerate_attack'，首先定义 attack_func：

def attack_func(p:tube, libc:ELF, l1, l2):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

然后使用该装饰器：

@local_enumerate_attack(argv="xxx.elf", libc_path="xxx.so", loop_time=1,loop_list=[[t11, t12, t13], [t21, t22]])
def attack_func(p:tube, libc:ELF, t1, t2):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

将执行：
    attack_func(process(argc), ELF(libc_path), t11, t21)
    attack_func(process(argc), ELF(libc_path), t12, t22)
    attack_func(process(argc), ELF(libc_path), t13, t21)
    attack_func(process(argc), ELF(libc_path), t21, t22)
    attack_func(process(argc), ELF(libc_path), t22, t21)
    attack_func(process(argc), ELF(libc_path), t22, t22)

或者使用：
@local_enumerate_attack(argv="xxx.elf", libc_path="xxx.so", loop_time=20, loop_list=None)
def attack_func(p:tube, libc:ELF):
    # ......
    if success:
        raise PwncliExit()
    else:
        raise RuntimeError()
    pass

将执行：
    for i in range(20):
        attack_func(process(argc), ELF(libc_path))
"""
