"""one_gadget 与 libc 路径探测。"""

import os
import re
import subprocess

from ..core.log import errlog_exit

__all__ = [
    "ldd_get_libc_path",
    "one_gadget",
    "one_gadget_binary",
]


def ldd_get_libc_path(filepath:str) -> str:
    """获取二进制文件所使用 libc.so.6 的真实路径。

    Args:
        filepath (str): 二进制文件路径。

    Returns:
        str: 该二进制文件所用 libc 的绝对路径。
    """
    rp = None
    try:
        out = subprocess.check_output(["ldd", filepath], encoding='utf-8').split()
        for o in out:
            if "/libc" in o:
                filedir = os.path.dirname(filepath)
                if o.startswith("/"):
                    rp = o
                else:
                    rp = os.path.realpath(os.path.join(filedir, o))
                break
    except:
        pass
    return rp


def one_gadget(condition:str, more=False, buildid=False):
    """通过执行 one_gadget 获取所有 one_gadget。

    Args:
        condition (str): libc.so 路径或 buildid。
        more (bool, optional): 是否获取更多 one_gadget，默认为 False。

    Yields:
        int: 每个 one_gadget 的地址。
    """
    cmd_list = ["one_gadget", "--raw"]
    if re.match(r"[0-9a-f]+",condition, re.I):
        buildid = True
    else:
        buildid = False
    if buildid:
        cmd_list.extend(["--build-id"])
    elif not os.path.exists(condition):
        errlog_exit("Cannot exec one_gadget, file `{}' not exists!".format(condition))


    cmd_list.extend([condition])

    if more:
        cmd_list.append("-l")
        cmd_list.append("2")
    try:
        res = subprocess.check_output(cmd_list, encoding='utf-8').split()
        return [int(i) for i in res]
    except:
        errlog_exit("Cannot exec one_gadget, maybe you don't install one_gadget or filename is wrong or buildid is wrong! cmd: {}".format(" ".join(cmd_list)))


def one_gadget_binary(binary_path:str, more=False):
    """获取一个 elf 二进制文件的所有 one_gadget。

    """
    binary_path = os.path.realpath(binary_path)
    rp = ldd_get_libc_path(binary_path)
    if rp:
        return one_gadget(rp, more)
    else:
        errlog_exit("Exec ldd {} fail!".format(binary_path))
