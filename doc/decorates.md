

# decorates — 装饰器

`pwncli/utils/decorates.py` 和 `pwncli/utils/cli_decorates.py` 提供各类实用装饰器。

***

## 1 爆破/枚举装饰器

### smart_enumerate_attack（脚本模式推荐）

```python
@smart_enumerate_attack(loop_time=0x10, loop_list=None, show_error=False)
def exploit():
    sla(b">> ", b"1")
    # ...
    if success:
        raise PwncliExit()  # 成功退出

exploit()
# 自动重试 0x10 次，每次创建新连接
```

带参数枚举（笛卡尔积）：

```python
@smart_enumerate_attack(loop_list=[[0x10, 0x20, 0x30], [1, 2]])
def exploit(offset, idx):
    sla(b">> ", str(offset).encode())
    raise PwncliExit()

exploit()
```

### local_enumerate_attack / remote_enumerate_attack（Library 模式）

```python
@local_enumerate_attack(argv="./pwn", libc_path="./libc.so.6", loop_time=20)
def attack(p: tube, libc: ELF):
    p.sendlineafter(b">> ", b"1")
    if success:
        raise PwncliExit()
    raise RuntimeError()  # 失败触发重试

@remote_enumerate_attack(ip="1.2.3.4", port=1337, libc_path="./libc.so.6", loop_time=20)
def attack(p: tube, libc: ELF):
    pass

# 带参数枚举
@local_enumerate_attack(argv="./pwn", libc_path="./libc.so.6", loop_list=[[1,2], [3,4]])
def attack(p: tube, libc: ELF, a, b):
    pass
```

***

## 2 控制流

```python
@bomber(seconds=10)                     # 超时退出
def slow_func(): ...

@bomber(seconds=10, callback=lambda: 0) # 超时返回 callback 结果
def slow_func(): ...

@retry(times=3)                         # 出错重试 3 次
def unstable(): ...

@limit_calls(times=1, warn_=True)       # 限调用 1 次
def init_once(): ...

@call_multimes(times=5, ignore_err=False)  # 连续调用 5 次
def send_pad(): ...

@always_success(show_err=True)          # 捕获异常不崩溃
def risky(): ...
```

***

## 3 计时和延迟

```python
@timer                        # 打印执行耗时
def heavy(): ...

@sleep_call_before(1)         # 调用前 sleep
def func(): ...

@sleep_call_after(1)          # 调用后 sleep
def func(): ...
# sleeper = sleep_call_after

@sleep_call_all(1)            # 前后各 sleep
def func(): ...
```

***

## 4 缓存

```python
@cache_result                 # 缓存首次返回值
def get_base(): ...

@cache_nonresult              # 仅缓存非 None 结果
def try_leak(): ...
```

***

## 5 其他

```python
@count_calls(show=True)       # 打印调用次数，func._num_calls 获取
def func(): ...

@show_name                    # 打印函数签名
def func(): ...

@deprecated("use new_func")   # 标记弃用
def old_func(): ...

@unused("will be removed")    # 标记未使用，调用返回 None
def dead_func(): ...

@add_prompt("sending payload")  # 调用前打印提示
def exploit(): ...

@signature2name               # 用签名作为 __name__
def func(): ...

@convert_str2bytes            # 将 str 参数转 bytes
def func(data): ...

@convert_bytes2str            # 将 bytes 参数转 str
def func(data): ...
```
