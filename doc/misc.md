

# misc — 基础工具集

`pwncli/utils/misc.py` 提供全局状态总线、打包解包增强、地址接收、日志、tcache 计算、safe linking 等基础工具。

***

## 1 gift 全局状态总线

增强的 `OrderedDict`，支持属性访问，是 pwncli 的核心状态总线。

```python
gift.io     # pwntools tube 对象
gift.elf    # 当前 ELF 对象
gift.libc   # libc ELF 对象

# 访问不存在的 key 返回 None（不抛异常）
gift.nonexistent  # -> None
```

### init_pwn_context — Library 模式初始化

```python
p = process("./pwn")
init_pwn_context(p, arch="amd64", log_level="debug")
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `io` | tube | pwntools tube 对象 |
| `arch` | str | 架构，默认 `"amd64"` |
| `**context_kwargs` | — | 传递给 `context.update()` |

自动默认：`log_level="debug"`、`endian="little"`、`timeout=5`、`os="linux"`。tmux 中自动配置 `context.terminal`。

***

## 2 打包/解包增强

### uN_ex — 宽松 unpack

接受不足 N 位的数据，自动补零：

```python
u64_ex(b"\x00\x10\x40")     # -> 0x401000
u32_ex(b"\xef\xbe")         # -> 0xbeef
u16_ex(b"\x41")             # -> 0x41
u8_ex(b"\xff")              # -> 0xff
u24_ex(b"\x01\x02")         # -> 0x0201
```

### pN_ex — 支持负数 pack

```python
p64_ex(-1)        # -> b'\xff\xff\xff\xff\xff\xff\xff\xff'
p32_ex(-100)      # -> b'\x9c\xff\xff\xff'
p16_ex(0x1234)    # -> b'\x34\x12'
p8_ex(0xff)       # -> b'\xff'
p24_ex(0x123456)  # -> b'\x56\x34\x12'
```

### 浮点数打包

```python
p64_float(3.14)                      # double -> 8 bytes
p32_float(3.14)                      # float -> 4 bytes
u64_float(b"\x00" * 8)              # 8 bytes -> double
u32_float(b"\x00" * 4)              # 4 bytes -> float

# 内存级别 float/int 互转（相同内存表示）
mem64_float2int(3735928559.0)        # double 的内存 int 表示
mem64_int2float(0x41ebd5b7dde00000)  # 反向
mem32_float2int(3735928559.0)
mem32_int2float(0x4f5eadbf)
```

### float_hexstr2int — 解析 printf %a 输出

```python
float_hexstr2int("0x0.07f6d266e9fbp-1022")  # -> 140106772946864
```

### pad 对齐

```python
pad_ljust(b"AAA", 8)         # -> b"AAA\x00\x00\x00\x00\x00" (右填充)
pad_rjust(b"AAA", 8)         # -> b"\x00\x00\x00\x00\x00AAA" (左填充)
```

### 进制转换与其他

```python
int16("deadbeef")            # -> 3735928559
int8("7654")                 # -> 4012
int2("11010110110")          # -> 1718
hex_ex(0x111)                # -> "0x0111" (偶数位补零)
flat_z({0: b"A", 0x10: b"B"})  # flat 的 filler=b"\x00" 版本
step_split("12345678", 4)    # 生成器: "1234", "5678"
```

***

## 3 地址接收

### recv_libc_addr

```python
libc_addr = recv_libc_addr(io, bits=64, offset=0, timeout=5)
# amd64: 接收到 \x7f，取后 6 字节 unpack
# i386:  接收到 \xf7，取后 4 字节 unpack
# 返回 unpack结果 - offset
```

### recv_addr_startswith_0x

```python
addr = recv_addr_startswith_0x(io, prefix="addr: ", suffix="\n", has_0x=True, timeout=5)
# 用正则从输出中提取 0x 开头的地址
```

### get_segment_base_addr_by_proc_maps

```python
addrs = get_segment_base_addr_by_proc_maps(pid, filename="pwn")
# 返回 dict: {'code': ..., 'libc': ..., 'ld': ..., 'heap': ..., 'stack': ..., 'vdso': ...}
```

***

## 4 日志函数

```python
log_ex("found: %s", hex(addr))          # [*] INFO  ...
log2_ex("important: %s", msg)           # [#] IMPORTANT INFO  ...
warn_ex("warning: %s", msg)             # [*] WARN  ...
errlog_ex("error: %s", msg)             # [!] ERROR ...
errlog_exit("fatal: %s", msg)           # 打印错误并 exit(-1)

# _highlight 后缀版本带背景高亮
log_ex_highlight(...)
warn_ex_highlight(...)

# 地址日志
log_address("libc_base", 0x7f...)       # [*] INFO  libc_base ===> 0x7f...
leak("libc_base", 0x7f...)              # 别名

# 自动获取变量名
libc_base = 0x7f0000000000
leak_ex("libc_base")                    # 通过栈帧反射
leak_ex2(libc_base)                     # 通过值反查变量名

# 预定义
log_libc_base_addr(addr)
log_heap_base_addr(addr)
log_code_base_addr(addr)
```

***

## 5 Tcache 计算器

```python
idx = calc_idx_tcache(chunksize=0x90, bits=64)

count_addr = calc_countaddr_tcache(
    chunksize=0x90,
    tcache_perthread_addr=heap_base + 0x10,
    sizeofcount=2,    # libc >= 2.31 用 2，之前用 1
    bits=64
)

entry_addr = calc_entryaddr_tcache(
    chunksize=0x90,
    tcache_perthread_addr=heap_base + 0x10,
    sizeofcount=2, bits=64
)

# 互相转换
count_addr = calc_countaddr_by_entryaddr_tcache(heap_base + 0x10, entry_addr)
entry_addr = calc_entryaddr_by_countaddr_tcache(heap_base + 0x10, count_addr)
```

### House of Corrosion

```python
chunksize = calc_chunksize_corrosion(targetaddr, main_arena_fastbinsY_addr, bits=64)
target = calc_targetaddr_corrosion(chunksize, main_arena_fastbinsY_addr, bits=64)
```

***

## 6 Safe Linking

```python
encrypted = protect_ptr(chunk_addr, next_ptr)   # (chunk_addr >> 12) ^ next_ptr
heap_addr = reveal_ptr(encrypted_value)          # 从泄露值还原堆地址
```

***

## 7 其他工具

### one_gadget

```python
gadgets = one_gadget("/path/to/libc.so.6", more=False)
gadgets = one_gadget("2a2cfed7ce39f3d517...", buildid=True)
gadgets = one_gadget_binary("./pwn", more=False)
```

### ldd_get_libc_path

```python
path = ldd_get_libc_path("./pwn")  # -> "/lib/x86_64-linux-gnu/libc.so.6"
```

### call_CDLL_func

```python
result = call_CDLL_func("", "rand")                    # 空路径用系统 libc
result = call_CDLL_func("/path/to/lib.so", "func", arg1)
```

### TimeoutPwncli

```python
with TimeoutPwncli(seconds=5, timeout_msg="Timeout!"):
    while True:
        do_something()
# 5 秒后抛出 TimeoutError
```
