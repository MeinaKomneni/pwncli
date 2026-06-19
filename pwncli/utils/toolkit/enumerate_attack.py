#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""本地/远程枚举攻击装饰器：自动探测 libc 并循环调用攻击函数。

local_enumerate_attack / remote_enumerate_attack 为公开装饰器，但不计入 __all__，
需通过 `from pwncli.utils.toolkit.enumerate_attack import local_enumerate_attack` 显式导入。
"""

import functools
import os
from enum import Enum, unique
from inspect import signature
from itertools import product
from typing import List

from pwn import ELF, process, remote, tube

try:
    from collections.abc import Iterable
except:
    from collections import Iterable

from ..core.exceptions import PwncliExit
from ..core.log import errlog_exit, log_ex
from .onegadget import ldd_get_libc_path

__all__: list[str] = []


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
