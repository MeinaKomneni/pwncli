"""字节/数字的打包解包、进制转换、浮点内存互转与填充。

以下函数的 doctest
>>> int16('deadbeef')
3735928559

>>> int16('0xdeadbeef')
3735928559

>>> int8('7654')
4012

>>> int2('11010110110')
1718

>>> int16_ex('deadbeef')
3735928559

>>> int16_ex(b'deadbeef')
3735928559

>>> int16_ex(b'0xdeadbeef')
3735928559

>>> int8_ex(b'7654')
4012

>>> int2_ex(b'11010110110')
1718
"""

import functools
import struct
import subprocess
import sys

from pwn import flat, pack, unpack

from .log import errlog_exit

__all__ = [
    # 偏函数
    "int16",
    "int8",
    "int2",
    "int16_ex",
    "int8_ex",
    "int2_ex",
    "int_ex",
    "flat_z",
    # pack 与 unpack 的增强函数
    "hex_ex",
    "float2str_pure",
    "u8_ex",
    "u16_ex",
    "u24_ex",
    "u32_ex",
    "u64_ex",
    "p8_ex",
    "p16_ex",
    "p24_ex",
    "p32_ex",
    "p64_ex",
    "p32_float",
    "p64_float",
    "u32_float",
    "u64_float",
    "pad_ljust",
    "pad_rjust",
    "float_hexstr2int",
    "mem64_float2int",
    "mem32_float2int",
    "mem64_int2float",
    "mem32_int2float",
    # 实用函数
    "step_split",
]

int16_ex = int16 = functools.partial(int, base=16)
int8_ex = int8 = functools.partial(int, base=8)
int2_ex = int2 = functools.partial(int, base=2)
int_ex = int

flat_z = functools.partial(flat, filler=b"\x00")


def step_split(s: str or bytes, step_len: int):
    """
    step_split("12345678", 4) -> "1234", "5678"
    step_split("1234567", 4) -> "1234", "567"
    """
    assert step_len > 0, "wrong step length!"
    start = 0
    end = start + step_len
    var = None
    while True:
        var = s[start:end]
        if len(var) != step_len:
            if len(var) != 0:
                yield var
            break
        yield var
        start = end
        end = start + step_len


def hex_ex(num: int) -> str:
    """hex_ex(0x0) -> 0x00

    hex_ex(0x111) -> 0x0111
    """
    s = hex(num)
    if len(s) % 2 == 0:
        return s
    return s[:2] + '0' + s[2:]

def float2str_pure(f: float):
    """float2str_pure(1.222e4) -> "12220.0"

    float2str_pure(1.222e-4) -> "0.0001222"
    """
    s = str(f)
    if 'e' in s:
        s2 = s.split('e')[1]
        s2 = int(s2)
        if s2 < 0:
            ff = "{" + ":.{}f".format(abs(s2-0x20)) + "}"
        else:
            ff = "{" + ":.{}f".format(0x20) + "}"
        return ff.format(f)
    else:
        return s

def u8_ex(data: str or bytes) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 1, "len(data) > 1!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(1, b"\x00")
    return unpack(data, 8)

def u16_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 2, "len(data) > 2!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(2, b"\x00")
    return unpack(data, 16, **kwargs)


def u24_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 3, "len(data) > 3!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(3, b"\x00")
    return unpack(data, 24, **kwargs)


def u32_ex(data: str or bytes, **kwargs) -> int:
    assert isinstance(data, (str, bytes)), "wrong data type!"
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(4, b"\x00")
    return unpack(data, 32, **kwargs)


def u64_ex(data: str or bytes, **kwargs) -> int:
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    data = data.ljust(8, b"\x00")
    return unpack(data, 64, **kwargs)


def p8_ex(num:int) -> bytes:
    if num < 0:
        num += 1 << 8
    num &= 0xff
    return pack(num, 8)


def p16_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 16
    num &= 0xffff
    return pack(num, 16, **kwargs)


def p24_ex(num: int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 24
    num &= 0xffffff
    return pack(num, 24, **kwargs)

def p32_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 32
    num &= 0xffffffff
    return pack(num, 32, **kwargs)


def p64_ex(num:int, **kwargs) -> bytes:
    if num < 0:
        num += 1 << 64
    num &= 0xffffffffffffffff
    return pack(num, 64, **kwargs)


def p32_float(num:float, endian="little") -> bytes:
    if endian.lower() == "little":
        return struct.pack("<f", num)
    elif endian.lower() == "big":
        return struct.pack(">f", num)
    else:
        raise RuntimeError("Wrong endian!")


def p64_float(num:float, endian="little") -> bytes:
    if endian.lower() == "little":
        return struct.pack("<d", num)
    elif endian.lower() == "big":
        return struct.pack(">d", num)
    else:
        raise RuntimeError("Wrong endian!")

def u32_float(data: bytes or str, endian="little") -> float:
    length = len(data)
    assert length <= 4, "len(data) > 4!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    if endian.lower() == "little":
        data = data.ljust(4, b"\x00")
        return struct.unpack("<f", data)[0]
    elif endian.lower() == "big":
        data = data.rjust(4, b"\x00")
        return struct.unpack(">f", data)[0]
    else:
        raise RuntimeError("Wrong endian!")


def u64_float(data: bytes or str, endian="little") -> float:
    length = len(data)
    assert length <= 8, "len(data) > 8!"
    assert isinstance(data, (str, bytes)), "wrong data type!"
    if isinstance(data, str):
        data = data.encode('latin-1')
    if endian.lower() == "little":
        data = data.ljust(8, b"\x00")
        return struct.unpack("<d", data)[0]
    elif endian.lower() == "big":
        data = data.rjust(8, b"\x00")
        return struct.unpack(">d", data)[0]
    else:
        raise RuntimeError("Wrong endian!")


def mem64_float2int(num:float, endian="little") -> int:
    """获取一个 double 数在相同内存布局下对应的整数。

    例如，0xdeadbeef 的内存为 0x41ebd5b7dde00000，mem64_float2int(0xdeadbeef) 得到 0x41ebd5b7dde00000"""
    return u64_ex(p64_float(num, endian))

def mem32_float2int(num:float, endian="little") -> int:
    """获取一个 float 数在相同内存布局下对应的整数。

    例如，0xdeadbeef 的内存为 0x4f5eadbf，mem32_float2int(0xdeadbeef) 得到 0x4f5eadbf"""
    return u32_ex(p32_float(num, endian))


def mem64_int2float(num: int, endian="little") -> float:
    """获取一个整数在相同内存布局下对应的 double 数。

    例如，0xdeadbeef 的内存为 0x41ebd5b7dde00000，mem64_int2float(0x41ebd5b7dde00000) 得到 0xdeadebeef"""
    res = u64_float(pack(num, endianness=endian, word_size=64))
    assert res != 0, "Invalid num!"
    return res

def mem32_int2float(num:float, endian="little") -> float:
    """获取一个整数在相同内存布局下对应的 double 数。

    例如，0xdeadbeef 的内存为 0x4f5eadbf，mem32_int2float(0x4f5eadbf) 得到 0xdeadbeef"""
    res = u32_float(pack(num, endianness=endian, word_size=32))
    assert res != 0, "Invalid num!"
    return res


def pad_ljust(payload: bytes or str, psz: int, filler: str="\x00") -> bytes:
    len_ = len(payload)
    comple = len_ % psz
    if comple > 0:
        return flat(payload, filler * (psz - comple))
    return payload

def pad_rjust(payload: bytes or str, psz: int, filler: str="\x00") -> bytes:
    len_ = len(payload)
    comple = len_ % psz
    if comple > 0:
        return flat(filler * (psz - comple), payload)
    return payload


def float_hexstr2int(data: str or bytes, hexstr=True, endian="little", bits=64) -> int:
    """float_hex2int('0x0.07f6d266e9fbp-1022') ---> 140106772946864

    用于 printf("%a")"""
    endian = endian.lower()
    assert endian in ("little", "big"), "only little or big for endian!"
    assert bits in (32, 64), "only 32 or 64 for bits!"

    if isinstance(data, bytes):
        data = data.decode()

    assert isinstance(data, str), "data is not str!"

    if endian == "little":
        ori = "<"
    else:
        ori = ">"

    if bits == 64:
        ch = "d"
    else:
        ch = "f"

    cmd = "from struct import pack\n"
    if hexstr:
        cmd += "a = float.fromhex('{}')\n"
    else:
        cmd += "a = float('{}')\n"

    cmd += "b = pack('{}{}', a)\n"
    cmd += "print(int.from_bytes(b, '{}'))"
    cmd = cmd.format(data, ori, ch, endian)
    try:
        res = subprocess.check_output([sys.executable, "-c", cmd]).strip()
        return int(res)
    except:
        errlog_exit("float_hex2int failed, check cmd: \n{}".format(cmd))


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)
