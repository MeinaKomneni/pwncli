

# consts — 常用 C/Linux 宏常量与系统调用号

***

## 快速使用

```python
from pwncli import Consts

# 直接取值
prot = Consts.mmap.PROT_READ | Consts.mmap.PROT_WRITE  # 0x3
flags = Consts.mmap.MAP_PRIVATE | Consts.mmap.MAP_ANONYMOUS  # 0x22

# 系统调用号
Consts.syscall.amd64.EXECVE   # 59
Consts.syscall.i386.OPENAT    # 295

# 打印某一组
Consts.show("mmap")
Consts.show("syscall")

# 打印全部
Consts.show()
```

***

## 常用组合

常用的几个组合：

```python
# ========== mmap: 开一块 RWX 内存写 shellcode ==========
# mmap(0, 0x1000, 7, 0x22, -1, 0)
#   prot  = PROT_READ|PROT_WRITE|PROT_EXEC = 7
#   flags = MAP_PRIVATE|MAP_ANONYMOUS       = 0x22
#   fd    = -1 (匿名映射不需要文件)
mmap(0, 0x1000, 7, 0x22, -1, 0)

# ========== mmap: 映射到固定地址 ==========
# mmap(0xdead0000, 0x1000, 7, 0x32, -1, 0)
#   flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED = 0x32
mmap(0xdead0000, 0x1000, 7, 0x32, -1, 0)

# ========== mprotect: 把某段改成可执行 ==========
# mprotect(page_addr, 0x1000, 7)
#   addr 必须页对齐 (addr & 0xfff == 0)
mprotect(buf_addr & ~0xfff, 0x1000, 7)

# ========== open + read + write: ORW 读 flag ==========
# fd = open("/flag", 0, 0)       O_RDONLY = 0
# read(fd, buf, 0x100)
# write(1, buf, 0x100)           stdout = 1

# ========== openat: 当 open 被 seccomp 禁了 ==========
# openat(-100, "/flag", 0, 0)    AT_FDCWD = -100 = 0xffffff9c

# ========== socket + connect: 反弹 shell ==========
# socket(2, 1, 0)                AF_INET=2, SOCK_STREAM=1
```

### 纯数字

打 ROP 时经常要手填立即数：

| 场景 | 参数 | 值 |
|------|------|----|
| mmap RWX 匿名 | prot=7, flags=0x22, fd=-1 | `7, 0x22, -1` |
| mmap RWX 固定地址 | prot=7, flags=0x32, fd=-1 | `7, 0x32, -1` |
| mprotect RWX | prot=7 | `7` |
| open 只读 | flags=0 | `0` |
| openat 当前目录 | dirfd=-100 | `-100` (0xffffff9c) |
| socket TCP | domain=2, type=1, proto=0 | `2, 1, 0` |
| execve | "/bin/sh"=0x68732f6e69622f | — |

***

## 包含的常量组

### mmap

`mmap(addr, length, prot, flags, fd, offset)`

| 宏名 | 值 | 说明 |
|------|-----|------|
| PROT_NONE | 0x0 | 不可访问 |
| PROT_READ | 0x1 | 可读 |
| PROT_WRITE | 0x2 | 可写 |
| PROT_EXEC | 0x4 | 可执行 |
| PROT_RWX | 0x7 | 读+写+执行 |
| MAP_SHARED | 0x01 | 共享映射 |
| MAP_PRIVATE | 0x02 | 私有映射（COW） |
| MAP_FIXED | 0x10 | 固定地址 |
| MAP_ANONYMOUS | 0x20 | 匿名映射（不关联文件） |
| MAP_ANON | 0x20 | 同上 |
| MAP_GROWSDOWN | 0x100 | 栈方向增长 |
| MAP_POPULATE | 0x8000 | 预填充页表 |
| MAP_STACK | 0x20000 | 用于栈 |

### open

`open(pathname, flags, mode)`

| 宏名 | 值 | 说明 |
|------|-----|------|
| O_RDONLY | 0 | 只读 |
| O_WRONLY | 1 | 只写 |
| O_RDWR | 2 | 读写 |
| O_CREAT | 0x40 | 不存在则创建 |
| O_EXCL | 0x80 | 与 O_CREAT 配合，文件已存在则失败 |
| O_TRUNC | 0x200 | 截断为零 |
| O_APPEND | 0x400 | 追加写 |
| O_NONBLOCK | 0x800 | 非阻塞 |
| O_DIRECTORY | 0x10000 | 必须是目录 |
| AT_FDCWD | -100 (0xffffff9c) | openat 的 "当前目录" 特殊值 |

### mprotect

`mprotect(addr, len, prot)` — prot 值同 mmap。

### signal

| 宏名 | 值 | | 宏名 | 值 |
|------|-----|-|------|-----|
| SIGHUP | 1 | | SIGKILL | 9 |
| SIGINT | 2 | | SIGSEGV | 11 |
| SIGQUIT | 3 | | SIGPIPE | 13 |
| SIGILL | 4 | | SIGALRM | 14 |
| SIGTRAP | 5 | | SIGTERM | 15 |
| SIGABRT | 6 | | SIGCHLD | 17 |
| SIGBUS | 7 | | SIGSTOP | 19 |

### socket

`socket(domain, type, protocol)`

| 宏名 | 值 | 说明 |
|------|-----|------|
| AF_UNIX | 1 | 本地套接字 |
| AF_INET | 2 | IPv4 |
| AF_INET6 | 10 | IPv6 |
| SOCK_STREAM | 1 | TCP |
| SOCK_DGRAM | 2 | UDP |
| SOCK_RAW | 3 | 原始套接字 |

### clone

| 宏名 | 值 |
|------|-----|
| CLONE_VM | 0x100 |
| CLONE_FS | 0x200 |
| CLONE_FILES | 0x400 |
| CLONE_SIGHAND | 0x800 |
| CLONE_THREAD | 0x10000 |
| CLONE_NEWNS | 0x20000 |
| CLONE_NEWPID | 0x20000000 |

### prctl / seccomp

| 宏名 | 值 | 说明 |
|------|-----|------|
| PR_SET_SECCOMP | 22 | 启用 seccomp |
| PR_SET_NO_NEW_PRIVS | 38 | 禁止提权（seccomp 前置条件） |
| SECCOMP_MODE_STRICT | 1 | 仅允许 read/write/exit/sigreturn |
| SECCOMP_MODE_FILTER | 2 | BPF 过滤模式 |

### ptrace

| 宏名 | 值 | | 宏名 | 值 |
|------|-----|-|------|-----|
| PTRACE_TRACEME | 0 | | PTRACE_GETREGS | 12 |
| PTRACE_PEEKTEXT | 1 | | PTRACE_SETREGS | 13 |
| PTRACE_PEEKDATA | 2 | | PTRACE_ATTACH | 16 |
| PTRACE_POKETEXT | 4 | | PTRACE_DETACH | 17 |
| PTRACE_CONT | 7 | | PTRACE_SINGLESTEP | 9 |

### syscall

i386 和 amd64 的系统调用号，打 ROP / SROP 时常用：

```python
Consts.syscall.amd64.READ       # 0
Consts.syscall.amd64.WRITE      # 1
Consts.syscall.amd64.OPEN       # 2
Consts.syscall.amd64.MPROTECT   # 10
Consts.syscall.amd64.EXECVE     # 59
Consts.syscall.amd64.OPENAT     # 257

Consts.syscall.i386.READ        # 3
Consts.syscall.i386.WRITE       # 4
Consts.syscall.i386.EXECVE      # 11
Consts.syscall.i386.MPROTECT    # 125
Consts.syscall.i386.OPENAT      # 295
```

常用调用号速查：

| 系统调用 | amd64 | i386 |
|----------|-------|------|
| READ | 0 | 3 |
| WRITE | 1 | 4 |
| OPEN | 2 | 5 |
| CLOSE | 3 | 6 |
| MMAP | 9 | 90 |
| MPROTECT | 10 | 125 |
| BRK | 12 | 45 |
| EXECVE | 59 | 11 |
| SOCKET | 41 | 359 |
| CONNECT | 42 | 362 |
| OPENAT | 257 | 295 |
| EXECVEAT | 322 | 358 |
| SECCOMP | 317 | 354 |

完整的调用号定义见 `pwncli/utils/consts.py` 的 `Consts.syscall` 内嵌类。
