"""堆相关纯算术：house of corrosion、tcache 偏移、safe-linking 指针保护。"""

__all__ = [
    # tcachebins 计算器
    "calc_chunksize_corrosion",
    "calc_targetaddr_corrosion",
    "calc_idx_tcache",
    "calc_countaddr_tcache",
    "calc_entryaddr_tcache",
    "calc_countaddr_by_entryaddr_tcache",
    "calc_entryaddr_by_countaddr_tcache",
    # safe linking 计算器
    "protect_ptr",
    "reveal_ptr",
]


def protect_ptr(address, next) -> int:
    return (address >> 12) ^ next

def reveal_ptr(addr) -> int:
    """
    addr = addr1 ^ addr2

    addr2 = addr1 + XXX

    计算堆地址
    """
    _res = addr
    for _ in range(3):
        _res = (_res >> 12) ^ addr
    return _res


def calc_chunksize_corrosion(targetaddr: int, main_arena_fastbinsY_addr: int, bits: int=64) -> int:
    """house of corrosion

    根据目标地址计算 chunksize
    """
    assert bits == 64 or bits == 32, "wrong bits!"
    assert targetaddr >= main_arena_fastbinsY_addr, "wrong addr!"
    assert targetaddr & ((bits >> 3) - 1) == 0, "target address not pad!"
    return (targetaddr - main_arena_fastbinsY_addr) * 2 + (bits >> 1)


def calc_targetaddr_corrosion(chunksize: int, main_arena_fastbinsY_addr: int, bits: int=64) -> int:
    """house of corrosion

    根据 chunksize 计算目标地址
    """
    assert bits == 64 or bits == 32, "wrong bits!"
    pad = bits >> 1
    assert chunksize & ((pad >> 1) - 1) == 0, "chunksize not pad!"
    assert chunksize >= pad, "wrong chunksize!"
    return ((chunksize - pad) >> 1) + main_arena_fastbinsY_addr


def calc_idx_tcache(chunksize: int, bits: int=64):
    """根据 chunksize 计算 tcache 中的索引"""
    assert bits == 64 or bits == 32, "wrong bits!"
    pad = bits >> 1
    assert chunksize & ((pad >> 1) - 1) == 0, "chunksize not pad!"
    assert chunksize >= pad, "invalid chunksize!"
    return (chunksize - pad) // (pad >> 1)


def calc_countaddr_tcache(chunksize: int, tcache_perthread_addr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010

    计算 &tcache->counts[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    idx = calc_idx_tcache(chunksize, bits)
    return idx * sizeofcount + tcache_perthread_addr


def calc_entryaddr_tcache(chunksize: int, tcache_perthread_addr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010

    计算 &tcache->entries[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    idx = calc_idx_tcache(chunksize, bits)
    start_addr = tcache_perthread_addr + sizeofcount * 64
    return idx * (bits >> 3) + start_addr


def calc_countaddr_by_entryaddr_tcache(tcache_perthread_addr: int, entryaddr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010

    根据 &tcache->entries[idx] 计算 &tcache->counts[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    start_addr = tcache_perthread_addr + sizeofcount * 64
    assert entryaddr >= start_addr, "invalid address!"
    dis = entryaddr - start_addr
    assert dis & ((bits >> 3) - 1) == 0, "distance not pad!"
    idx = dis // (bits >> 3)
    return idx * sizeofcount + tcache_perthread_addr


def calc_entryaddr_by_countaddr_tcache(tcache_perthread_addr: int, countaddr: int, sizeofcount: int=2, bits: int=64):
    """tcache_perthread_addr: 0x555555555010

    根据 &tcache->counts[idx] 计算 &tcache->entries[idx]
    """
    assert sizeofcount == 1 or sizeofcount == 2, "glibc version >= 2.31, sizeof(count) = 2, otherwise 1"
    assert countaddr >= tcache_perthread_addr, "invalid address!"
    dis = countaddr - tcache_perthread_addr
    assert dis & (sizeofcount - 1) == 0, "distance not pad!"
    idx = dis // sizeofcount
    start_addr = tcache_perthread_addr + sizeofcount * 64
    return idx * (bits >> 3) + start_addr
