#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : bruteforce.py
@Time    : 2021/11/23 23:48:49
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : bruteforce methods
'''



import typing
from string import printable

from pwnlib.util.hashes import *
from pwnlib.util.iters import bruteforce, mbruteforce

from ..core.log import errlog_exit

__all__ = [
    "bruteforce_hash",
    "mbruteforce_hash"
]

_hash_algos = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
)

#--------------------hash 相关----------------------
def __inner_bruteforce(hash_algo:str, prefix_str:str, suffix_str: str, check_res_func:typing.Callable, 
        alphabet:str, start_length:int, max_length:int, multithread):
    assert max_length >= start_length
    assert isinstance(prefix_str, str)
    assert isinstance(alphabet, str)

    if hash_algo not in _hash_algos:
        errlog_exit("Hash algo error, only support for: {}".format(_hash_algos))

    def func(s):
        hash_func = globals()[hash_algo+"sumhex"]
        res = hash_func((prefix_str + s + suffix_str).encode('latin-1'))
        return check_res_func(res)
    
    res = None
    for length in range(start_length, max_length+1):
        _use_func = mbruteforce if multithread else bruteforce
        res = _use_func(func, alphabet, length, method='fixed')
        if res:
            break
    return res


def bruteforce_hash(hash_algo:str, prefix_str:str, suffix_str: str, check_res_func:typing.Callable, 
        alphabet:str=printable.strip(), start_length:int=4, max_length:int=6):
    """在已知前缀字符串时爆破哈希值，如 sha256('eRt<'+?) 以 000000 开头

    Args:
        hash_algo (str): 哈希算法名：[md5, sha1, sha224, sha256, sha384, sha512]。
        prefix_str (str): 前缀字符串。
        suffix_str (str): 后缀字符串。
        check_res_func (typing.Callable): 检查哈希值的函数，如：lambda x: x.startswith('000000')。
        alphabet (str, optional): 使用的字符集，默认为 printable.strip()。
        start_length (int, optional): 起始长度，默认为 4。
        max_length (int, optional): 最大长度，默认为 6。

    Returns:
        str: 未找到则返回 None。

    Example:
        >>> res = bruteforce_hash_prefixstr("sha256", "eRt<", "",lambda x: x.startswith("0000"), max_length=4)
        >>> res
        '02)T'
        >>> sha256sumhex(("eRt<"+res).encode()).startswith("0000")
        True
    """
    return __inner_bruteforce(hash_algo, prefix_str, suffix_str, check_res_func, alphabet, start_length, max_length, False)


def mbruteforce_hash(hash_algo:str, prefix_str:str, suffix_str: str, check_res_func:typing.Callable,
        alphabet:str=printable.strip(), start_length:int=4, max_length:int=6):
    """在已知前缀字符串时爆破哈希值，如 sha256('eRt<'+?) 以 000000 开头

    Args:
        hash_algo (str): 哈希算法名：[md5, sha1, sha224, sha256, sha384, sha512]。
        prefix_str (str): 前缀字符串。
        suffix_str (str): 后缀字符串。
        check_res_func (typing.Callable): 检查哈希值的函数，如：lambda x: x.startswith('000000')。
        alphabet (str, optional): 使用的字符集，默认为 printable.strip()。
        start_length (int, optional): 起始长度，默认为 4。
        max_length (int, optional): 最大长度，默认为 6。

    Returns:
        str: 未找到则返回 None。

    Example:
        >>> res = mbruteforce_hash_prefixstr("sha256", "eRt<", "", lambda x: x.startswith("000000"), max_length=6)
        >>> res
        '0_TR'
        >>> sha256sumhex(("eRt<"+res).encode()).startswith("000000")
        True
    """
    return __inner_bruteforce(hash_algo, prefix_str, suffix_str,check_res_func, alphabet, start_length, max_length, True)

    
if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)