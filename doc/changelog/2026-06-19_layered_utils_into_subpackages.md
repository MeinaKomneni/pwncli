# utils 目录分层为 core / toolkit / runtime 三子包

## 动机

`pwncli/utils/` 此前是 23 个扁平 .py 文件平铺在同一层，通用底座（log、packing）、PWN 利用构件（io_file、gadgetbox）、当前会话操作（current_gadgets、current_gdb）混在一起，没有边界。这是目录分层问题——和早先 misc.py、cli_misc.py 的内聚性问题不同：那些是「一个文件塞多职责」，这次是「一个目录没有层次」。

此前没动它，是因为「按用途分类没有客观边界」——比如 io_file 零内部依赖却是高层利用工具，按「基础设施 vs 一把梭」归类会陷入主观扯皮。本次借助框架讨论确立了一个**客观分层依据**：不按用途，而按「模块在框架中的角色层次」——通用底座 → 利用原语 → 当前会话操作，由两个硬标准裁定：依赖方向（下层被上层调用）、是否绑定当前题目会话（gift）。依此 io_file 明确归利用原语层，不再含糊。

## 方案

按依赖图与「是否绑定 gift」两个客观标准，把 23 个模块分入三个子包：

| 子包 | 角色 | 模块 | 裁定标准 |
|------|------|------|----------|
| `core/` | 通用底座 | log packing encoding env state consts exceptions config | 无 PWN 语义、不引用 gift |
| `toolkit/` | 利用构件 | gadgetbox onegadget libcbox shellcode io_file heapcalc recv bruteforce decorates pipes | PWN 构件、不绑定当前会话 |
| `runtime/` | 当前会话操作 | current_session current_gdb current_gadgets gdb_helper cli_decorates | 操作当前题目 gift |

依赖方向严格单向：`runtime → toolkit → core`，无环。core 内部仅 `state→env`、`packing→log`；toolkit 内部 `libcbox→gadgetbox/onegadget`、`decorates→onegadget`、`pipes→decorates`；runtime 内部 `current_gdb→current_session/gdb_helper`、`cli_decorates→current_session`。无一条向上依赖。

## API

公共 API 完全不变。`from pwncli import *` 导出符号数维持 513；`utils/__init__.py` 经三个子包 `__init__.py` 聚合 re-export，对外仍是扁平命名空间。

变化的是直接子模块路径：`pwncli/utils/io_file.py` → `pwncli/utils/toolkit/io_file.py` 等。沿用既定决策（大部分用户写 `from pwncli import *`，直接 import 可断），不保留兼容垫片。外部脚本里 `from pwncli.utils.io_file import ...` 需改为 `from pwncli.utils.toolkit.io_file import ...`。

## 改动文件

- 新增三个子包目录及其 `__init__.py`：`utils/core/`、`utils/toolkit/`、`utils/runtime/`
- 迁移 23 个模块文件入对应子包
- 重写各模块内部相对 import：同子包 `from .X import`；跨子包 `from ..<子包>.X import`
- 重写 `utils/__init__.py`：从三子包聚合
- 改写消费者 import：`pwncli/cli.py`、`pwncli/commands/cmd_*.py`（12 个）、`tests/heap/*.py`（8 个）、`tests/util_test/test_recent_features.py`

## 实现要点

一是用迁移脚本而非手工。建包、移动、重写内部 import 用一个脚本完成：脚本按「模块名→子包」映射，对每个文件的 `from .X import` 行，按 X 与本模块是否同子包决定写成 `from .X import` 或 `from ..<子包>.X import`。消费者改写用另一个脚本，两条规则覆盖三种路径形态（`.utils.X` / `..utils.X` / `pwncli.utils.X`）统一插入子包层，并特判 `from pwncli.utils import current_gdb`（导入模块对象）→ `from pwncli.utils.runtime import current_gdb`。

二是子包 `__init__.py` 的导入序按依赖拓扑排。core 叶优先（env/log 先于 packing/state）；toolkit 中 gadgetbox、onegadget 先于 libcbox/decorates，decorates 先于 pipes；runtime 中 current_session/gdb_helper/current_gadgets 先于 current_gdb/cli_decorates。避免导入期半初始化。

三是 utils 内部一律 `from .<模块> import` / `from ..<子包>.<模块> import` 直连，不走 `from . import`（沿用前两次重构约定）。

## 验证

`from pwncli import *` 符号数 513 不变；三层子包路径（`pwncli.utils.core.state`、`pwncli.utils.toolkit.io_file`、`pwncli.utils.runtime.current_gadgets`）可用且对象身份一致；13 个 CLI 命令全部可导入；pytest 收集 50 用例 0 错误；util_test 排除网络依赖的 test_libcbox 后 45 passed / 1 skipped。test_libcbox 失败在 libc 二进制下载超时（下载逻辑未改动，测试能到达下载阶段即证明 LibcBox 导入正常），属环境网络问题，非本次重构回归。
