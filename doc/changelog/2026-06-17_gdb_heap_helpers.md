# 2026-06-17: gdb_cmd 增加 remote 自动禁用与堆地址快捷函数

## 动机

有了 `gdb_cmd` 之后，希望进一步封装出堆相关的快捷函数（实时取 top chunk、heap base、bins、heap 全量输出），让 AI 在打 heap 题时能直接拿到结构化信息而非肉眼读 pwndbg 表格。同时，本地 debug 写好的堆调试代码切到 remote 打同一道题时会因没有本地 gdb 而出错，需要自动禁用。

## 方案

`gdb_cmd` 作为底层，派生函数在其之上封装；remote 模式守卫集中在 `gdb_cmd` 入口，派生函数自动继承。

## API

```python
# 通用：发命令、取输出（默认打印）
out = gdb_cmd("heap")
out = gdb_cmd("p $_base", quiet=True)              # 静默
out = gdb_cmd("heap", capture_lines=1000)           # 长输出，清滚动缓冲后抓取

# 堆地址（基于 pwndbg.aglib.heap.current，返回 int，失败返回 0）
top  = gdb_top_chunk_addr()    # main_arena.top
base = gdb_heap_base()         # main_arena.active_heap.start

# 堆布局原始输出（默认打印并返回字符串）
bins_out = gdb_bins()
heap_out = gdb_heap()
```

remote 模式下（`gift['remote']` 为真）以上函数全部 warn 并返回空值/0，不抛异常。

## 改动文件

- `pwncli/utils/cli_misc.py`：`gdb_cmd` 加 `remote` 守卫与 `capture_lines` 参数；新增 `gdb_top_chunk_addr`、`gdb_heap_base`、`gdb_bins`、`gdb_heap`、`_parse_hex_int`；更新 `__all__`
- `doc/cli_misc.md`：补充四个新函数与 remote 禁用说明

## 实现要点

- **remote 守卫**：`gdb_cmd` 入口检查 `gift.get('remote')`，remote 时 warn 并返回空。派生函数调用 `gdb_cmd`，自动继承禁用行为，无需各自重复判定。
- **长输出捕获**：`capture_lines > 0` 时，顺序为 Ctrl-L 清屏（把可见区推入 scrollback）→ `clear-history` 清 scrollback → 发命令 → `capture-pane -S -N` 抓取。顺序不能反：若先 `clear-history` 再 Ctrl-L，C-l 推入的旧内容（可能含上一次同命令的回显）会留在 scrollback，导致剥离时命中旧回显。
- **输出剥离**：定位命令回显行（`pwndbg> <cmd>`，去掉 prompt 前缀后以 cmd 开头），丢弃到该行（含），取其后内容。这样即便 scrollback 里残留旧内容，也会被回显行隔开丢掉。重复调用同一命令不再命中旧回显。
- **堆地址走 API 不走文本**：`gdb_top_chunk_addr`/`gdb_heap_base` 发 `py print(hex(pwndbg.aglib.heap.current.main_arena.top))` 取干净整数，`_parse_hex_int` 用正则提取首个 `0x..`，避免解析 pwndbg 表格文本的脆性。
- **实测验证**：pwndbg 2026.02.18 下，`main_arena.top`、`main_arena.active_heap.start` 均返回正确 int；`gdb_heap` 输出末尾的 Top chunk 地址与 `gdb_top_chunk_addr()` 交叉一致。
- **capture_lines 副作用**：清 scrollback 会破坏 pane 滚动历史，文档已注明。
