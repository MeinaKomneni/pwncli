

# pipes — 命名管道通信

`pwncli/utils/pipes.py` 提供 FIFO 管道的 pwntools 风格 API，用于进程间通信。

***

## 用法

```python
pipe = NamedPipePair(
    rpath="/tmp/fifo_r",    # 读管道路径
    wpath="/tmp/fifo_w",    # 写管道路径
    log_level="debug",      # "debug" 打印收发数据
    created=True,           # 不存在时自动创建 FIFO
    deleted=True            # 析构时自动删除
)

# 发送
pipe.send(b"data", timeout=15)
pipe.sendline(b"data", timeout=15)

# 接收
data = pipe.recv(1024, timeout=5)
data = pipe.recvall(timeout=3)
line = pipe.recvline(drop=False, timeout=5)
data = pipe.recvuntil(b"marker", timeout=5)

# 交互式
pipe.sendafter(b"prompt: ", b"input", timeout=5)
pipe.sendlineafter(b"prompt: ", b"input", timeout=5)
```

## 参数说明

| 构造参数 | 类型 | 说明 |
|----------|------|------|
| `rpath` | str | 读管道路径 |
| `wpath` | str | 写管道路径 |
| `log_level` | str | `"debug"` 打印 hexdump |
| `created` | bool | 管道不存在时自动创建，默认 `True` |
| `deleted` | bool | 析构时删除管道文件，默认 `True` |
