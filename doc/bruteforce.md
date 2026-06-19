

# bruteforce — 哈希爆破

`pwncli/utils/toolkit/bruteforce.py` 用于 CTF 中常见的 PoW (Proof of Work) 验证。

***

## 用法

```python
# 单线程
res = bruteforce_hash(
    hash_algo="sha256",
    prefix_str="eRt<",
    suffix_str="",
    check_res_func=lambda x: x.startswith("000000"),
    alphabet=printable.strip(),
    start_length=4,
    max_length=6
)
# res 使得 sha256("eRt<" + res) 以 "000000" 开头

# 多线程（推荐）
res = mbruteforce_hash(
    hash_algo="sha256",
    prefix_str="eRt<",
    suffix_str="",
    check_res_func=lambda x: x.startswith("000000"),
    max_length=6
)
```

## 参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `hash_algo` | str | `md5`/`sha1`/`sha224`/`sha256`/`sha384`/`sha512` |
| `prefix_str` | str | 已知前缀 |
| `suffix_str` | str | 已知后缀 |
| `check_res_func` | Callable | 校验函数，接收 hex hash 字符串，返回 bool |
| `alphabet` | str | 字符集，默认 `printable.strip()` |
| `start_length` | int | 起始爆破长度，默认 4 |
| `max_length` | int | 最大爆破长度，默认 6 |

**返回值**：找到的字符串，或 `None`。

## 示例：常见 PoW

```python
# sha256(prefix + ???) 前 6 位为 0
io.recvuntil(b"sha256(")
prefix = io.recvuntil(b" + ", drop=True).decode()
io.recvuntil(b"== ")
target = io.recvline(keepends=False).decode()

res = mbruteforce_hash("sha256", prefix, "", lambda x: x.startswith(target))
io.sendline(res.encode())
```
