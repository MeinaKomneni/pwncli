# 拍平 current_gadgets.py：去嵌套、去 else/if 链、去重复

## 动机

`pwncli/utils/runtime/current_gadgets.py` 有几处反 Linus 结构：`_initial_gadgetbox` 里 elf 与 libc 两块同构代码各嵌 4 层、`__inner_chain` 里 i386/amd64 两大分支结构同构、`_internal_find` 与 `find_gadget` 控制流重复、`write_by_magic` 与 `ret2csu` 深嵌套，外加约 15 处裸 `except:`。这些让模块难读难改。按 guard clause 早返回、消去 `else`、同构分支抽共享体、去重复拍平，严格保持 ROP 链产出逐字节不变。

## 方案

1. **`_initial_gadgetbox`**：抽内部闭包 `_add_one(name, obj)` 消去 elf/libc 两块重复，`if arch not in: ... else:` 改 guard clause 早返回，`if ropper: ... else:` 改一行三元取 `arch_arg`。嵌套从 4 层降到 1 层。

2. **`__inner_chain`**：i386/amd64 两大分支用 per-arch 配置（位宽、syscall 号、arg1 寄存器、arg2/arg3 gadget）+ 共享体合并。唯一语义差异——i386 的 rdx gadget 需 `rbx_val=para1`——用 `arg3` lambda 捕获 `para1` 表达。

3. **`_internal_find` / `find_gadget`**：抽 `_search(make_call)` 静态方法统一「elf→libc 试探」控制流（set imagebase → 试 elf 吞异常 → 试 libc 抛出），两者只保留各自的选 func 与未命中报错差异。用模块级哨兵 `_NEITHER` 区分「两者都未试」与「找不到」，调用方据此决定 `log2_ex` 还是 `errlog_exit`。

4. **`write_by_magic`**：`if amd64: if short: ... else: ... else:` 三层合并成一层。delta 逻辑 `expected-ori if expected>ori else expected-ori+0x100000000` 等价化简为 `delta=expected-ori; if delta<=0: delta+=0x100000000`（含相等情形一致）。

5. **`ret2csu`**：四层嵌套循环 `for reg: for x: if reg in x: if mov: if di/si/dx: ...` 用 `continue`/`break` 拍平。结构 assert 保证每个 reg 恰命中一行，break 等价。

6. **裸 `except:` 清扫**：约 15 处改 `except Exception:`（不吞 `KeyboardInterrupt`/`SystemExit`）。`pop_pop_ret`/`pop_pop_pop_ret`/`__try_get_rdx_gadget` 的「前几个 try、最后一个无条件返回」try 链用循环表达。

## API

无变化。公共方法名、签名、`__all__` 不变。新增 `_search`（私有静态方法）与模块级哨兵 `_NEITHER`，不导出。

## 改动文件

仅 `pwncli/utils/runtime/current_gadgets.py`（净减约 58 行）。

## 实现要点

- `_add_one` 作为 `_initial_gadgetbox` 内闭包，捕获 `__arch_mapping`；`res = _add_one("elf", elf) or res` 两次调用都执行（`or` 左操作数总求值），副作用顺序与原 elf→libc 一致，`__arch` 最终值为 libc.arch（与原一致）。
- `__inner_chain` 的 `arg3` lambda 捕获 `para1`：i386 路径 `__try_get_rdx_gadget(para3, para1)` 的第二参数仍为 para1，amd64 路径 `__try_get_rdx_gadget(para3)` 不变。
- `_search` 保留原「elf 试探吞异常、libc 不吞直接抛」的语义；elf 路径的裸 `except` 顺手改 `except Exception`，KeyboardInterrupt 现会向上传播而非静默 fall through（更正确）。
- `write_by_magic` 的 delta 化简在 `expected == ori` 时原走 else（+0x100000000），新逻辑 `delta<=0` 也 +0x100000000，一致。
- `ret2csu` 的 break 依赖 `newlen-oldlen==4` 与结构 assert，每个 reg 恰命中一行，break 与原「遍历所有行」等价。

## 验证

真实 ROP 端到端：`test_gadget_chains_real.py` 三用例（execve_chain getshell、orw_chain 读 flag、local_enumerate_attack 装饰器）全过，证明链产出逐字节不变；全量 util_test（排除网络依赖的 test_libcbox）48 passed / 1 skipped；`__all__` 仍 513；pyflakes 无 undefined name。
