# 修复 CurrentGadgets 初始化时 ropper 后端误用 elf.arch

## 动机

`CurrentGadgets._initial_gadgetbox` 在加载 libc 时，若 gadget 后端为 ropper，调用
`add_file("libc", libc.path, __arch_mapping[elf.arch])`。此处应取 `libc.arch`，
却误用了 `elf.arch`。当 gift 中只有 libc、没有 elf（`elf is None`）时，该行直接抛
`AttributeError`，导致仅基于 libc 的 gadget 搜索在 ropper 后端下不可用。

该路径在常规环境下不可达：后端选择顺序为 RopgadgetBox → ElfGadgetBox → RopperBox，
而 ElfGadgetBox 的 `__init__` 不会抛异常，故实际几乎不会落到 ropper。但这是一处真实
的潜伏缺陷，留着迟早踩到。

## 方案

将 `__arch_mapping[elf.arch]` 改为 `__arch_mapping[libc.arch]`，与同分支 else 子句
（非 ropper 后端）及 elf 分支的取值逻辑保持一致。

## API

无变化。

## 改动文件

- `utils/runtime/current_gadgets.py`：libc+ropper 分支取 `libc.arch`

## 实现要点

仅一行。elf 分支用 `elf.arch` 是正确的（该分支已确认 elf 非 None）；libc 分支必须用
`libc.arch`，否则 elf 缺失时崩溃，elf 存在时也只是"恰好同架构"而碰巧可用。

## 验证

`tests/util_test` 全量 52 passed / 1 skipped；新增 `test_gadget_chains_real.py`
以真实 ROP（execve_chain getshell、orw_chain 读 flag、local_enumerate_attack 装饰器
机制）端到端验证链构造器在重构后仍正确。
