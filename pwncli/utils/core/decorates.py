#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""通用装饰器：与 PWN 语义无关的函数装饰工具（计时、重试、缓存、超时等）。"""

import functools
import signal
import sys
import time
from enum import Enum, unique
from typing import Callable

from .log import get_func_signature_str, log_ex, warn_ex_highlight


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
