

# cli_misc — 脚本模式工具集

`pwncli/utils/cli_misc.py` 提供围绕 `gift` 全局状态的脚本模式工具：IO 快捷方式、地址管理、GDB 操作、CurrentGadgets 等。

***

## 1 IO 快捷方式

所有快捷方式操作 `gift.io`，可通过 `switch_io(other_tube)` 切换目标。

| 函数 | 等效 | 说明 |
|------|------|------|
| `s(data)` | `io.send(data)` | 发送 |
| `sl(data)` | `io.sendline(data)` | 发送+换行 |
| `sa(delim, data)` | `io.sendafter(delim, data)` | 收到 delim 后发送 |
| `sla(delim, data)` | `io.sendlineafter(delim, data)` | 收到 delim 后发送+换行 |
| `st(delim, data)` | `io.sendthen(delim, data)` | 发送后收到 delim |
| `slt(delim, data)` | `io.sendlinethen(delim, data)` | 发送+换行后收到 delim |
| `ru(delim)` | `io.recvuntil(delim)` | 收到 delim |
| `rl()` | `io.recvline()` | 收一行 |
| `rs(n)` | `io.recvlines(n)` | 收 n 行 |
| `rls(prefix)` | `io.recvline_startswith(prefix)` | 收以 prefix 开头的行 |
| `rle(suffix)` | `io.recvline_endswith(suffix)` | 收以 suffix 结尾的行 |
| `rlc(s)` | `io.recvline_contains(s)` | 收包含 s 的行 |
| `ra()` | `io.recvall()` | 收全部 |
| `rr(regex)` | `io.recvregex(regex)` | 正则收 |
| `r(n)` | `io.recv(n)` | 收 n 字节 |
| `rn(n)` | `io.recvn(n)` | 精确收 n 字节 |
| `ia()` | `io.interactive()` | 进入交互 |
| `ic()` | `io.close()` | 关闭连接 |
| `cr()` | `io.can_recv()` | 检查可读 |

```python
sla(b">> ", b"1")
ru(b"addr: ")
addr = int(rl(), 16)
```

### switch_io / copy_current_io

```python
io2 = remote("127.0.0.1", 1234)
switch_io(io2)       # 之后 s/sl/ru 等操作 io2
switch_io(gift.io)   # 切回

new_io = copy_current_io()  # 按原始参数创建新连接
```

***

## 2 地址管理

### set_current_libc_base

```python
base = set_current_libc_base(addr=leaked_addr, offset=libc.sym['puts'])
base = set_current_libc_base(addr=leaked_addr, offset='puts')  # 符号名
base = set_current_libc_base()  # 自动 recv
base = set_current_libc_base_and_log(addr=leaked_addr, offset='puts')  # 设置并打印
```

### set_current_code_base

```python
base = set_current_code_base(addr=leaked_addr, offset=0x1234)
base = set_current_code_base_and_log(addr=leaked_addr, offset='main')
```

### set_remote_libc

```python
libc = set_remote_libc("./libc.so.6")  # 仅 remote 模式
```

### 读取 /proc/pid/maps（仅 debug 模式）

```python
code_base  = get_current_codebase_addr(use_cache=True)
libc_base  = get_current_libcbase_addr(use_cache=True)
heap_base  = get_current_heapbase_addr(use_cache=True)
stack_base = get_current_stackbase_addr(use_cache=True)
```

### recv_current_libc_addr

```python
addr = recv_current_libc_addr(offset=libc.sym['puts'], timeout=5)
```

### one_gadget 快捷方式

```python
gadgets = get_current_one_gadget_from_file(libc_base=0, more=False)
gadgets = get_current_one_gadget_from_libc(more=False)
```

***

## 3 GDB 操作

以下函数仅在 debug+gdb 模式下生效（`@only_gdb`）：

```python
execute_cmd_in_current_gdb("b *0x401234; c")
set_current_pie_breakpoints(offset=0x1234)         # 需 pwndbg
tele_current_pie_content(offset=0x1234, number=10)
send_signal2current_gdbprocess(sig_val=2)
send_continue2current_gdbprocess()
kill_current_gdb()
```

无 gdb 时手动启动（`@only_nogdb`）：

```python
launch_current_gdb(gdbscript="b *main\nc", stop_=True)
```

### attach_existing_process

附加 gdb 到一个已经在运行的进程，不依赖 pwncli 的 debug 模式。`target` 可以是 pid（int），也可以是进程名（str）。给进程名时按 comm 做精确匹配；匹配到多个进程时会给出告警并选取 pid 最小的那一个。

```python
# 按 pid 附加
attach_existing_process(1234, gdbscript="b *main\nc")

# 按进程名附加（重名时告警并取第一个）
attach_existing_process("pwn_binary", gdbscript="c", stop_=False)
```

进程名解析依赖系统的 `pgrep`。注意内核里 comm 字段最长 15 个字符，过长的进程名需用其截断后的名字或直接用 pid。

### 动态定义结构体

```python
add_struct2current_gdb_by_member(
    "struct student", True,
    "char *teachers[10]",
    name="i8 *", id="u64", grade="size_t"
)

add_struct2current_gdb_by_file("""
typedef struct { int id; char name[32]; } student_t;
""", True, "student_t")

add_show_struct_command2current_gdb("struct student")
# GDB 中执行: pwncli_show_student 0x7fffffffde00
```

***

## 4 stop 断点

```python
stop()            # 打印调用位置，等待按键继续
S()               # 别名
stop(enable=False) # 条件跳过
```

***

## 5 Heaptrace 集成

```python
launch_heaptrace(stop_=True, malloc_off='', free_off='', realloc_off='')
kill_heaptrace()
```

仅 debug 无 gdb 模式下可用。自动检测 tmux/WSL/gnome-terminal 环境。

***

## 6 模式限定装饰器

```python
@only_debug()              # 仅 debug 模式
@only_gdb()                # 仅 debug + gdb
@only_nogdb()              # 仅 debug 无 gdb
@only_remote()             # 仅 remote 模式
@only_debug_or_remote()    # debug 或 remote
```

### call_current_CDLL_func

```python
result = call_current_CDLL_func("rand")  # 自动使用 gift.libc.path
```
