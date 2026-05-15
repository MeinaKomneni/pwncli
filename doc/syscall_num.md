

# syscall_num — 系统调用号常量

`pwncli/utils/syscall_num.py` 提供 i386 和 amd64 的系统调用号。

***

## 用法

```python
SyscallNumber.amd64.READ       # 0
SyscallNumber.amd64.WRITE      # 1
SyscallNumber.amd64.OPEN       # 2
SyscallNumber.amd64.CLOSE      # 3
SyscallNumber.amd64.MPROTECT   # 10
SyscallNumber.amd64.EXECVE     # 59
SyscallNumber.amd64.OPENAT     # 257

SyscallNumber.i386.READ        # 3
SyscallNumber.i386.WRITE       # 4
SyscallNumber.i386.OPEN        # 5
SyscallNumber.i386.EXECVE      # 11
SyscallNumber.i386.MPROTECT    # 125
SyscallNumber.i386.OPENAT      # 295
```

## 常用调用号速查

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
