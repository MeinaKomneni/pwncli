

# libcbox — 在线 Libc 搜索

`pwncli/utils/toolkit/libcbox.py` 通过 [libc.rip](https://libc.rip) API 根据泄露的符号地址搜索 libc 版本。

***

## 基本用法

```python
lb = LibcBox(debug=True)

# 添加约束（低 12 位匹配）
lb.add_symbol("puts", 0x7f1234567a30)
lb.add_symbol("printf", 0x7f1234567b40)

# 也可用 hash 约束
lb.add_buildid("2a2cfed7ce39f3d517...")
lb.add_md5("...")
lb.add_sha1("...")
lb.add_sha256("...")
```

### 搜索

```python
lb.search(
    download_symbols=False,   # 下载符号文件
    download_so=False,        # 下载 .so
    download_deb=False,       # 下载 .deb
    version_start="2.23",     # 过滤 >= 2.23
    load_gadgets=False,       # 加载 gadget
    wait_=True                # 等待下载完成
)
# 多个匹配时会交互式选择
```

### 查询符号

```python
puts_off   = lb.dump("puts")
system_off = lb.dump("system")
binsh_off  = lb.dump_str_bin_sh()
```

### one_gadget

```python
gadgets = lb.dump_one_gadget(libc_base=0x7f0000000000, more=False)
```

### gadget 搜索

```python
box = lb.get_gadgetbox(debug=False)
addr = box.search_opcode("5fc3", "libc")
```

### 重置

```python
lb.reset()
```

***

## 参数说明

| 构造参数 | 类型 | 说明 |
|----------|------|------|
| `search_url` | str | API 地址，默认 `"https://libc.rip/api/find"` |
| `debug` | bool | 打印调试信息 |
| `wait_time` | int | 下载超时秒数，默认 45 |

支持链式调用：`lb.add_symbol("puts", addr).add_symbol("printf", addr)`
