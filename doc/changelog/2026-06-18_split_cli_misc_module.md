# 拆解 utils/cli_misc.py 为三个按职责命名的模块

## 动机

`pwncli/utils/cli_misc.py` 累积到 1687 行，比早先被拆掉的 misc.py 还大，且把两个毫不相干的关注点焊在一起：一个是 740 行的 `CurrentGadgets`（纯 ROP 链构建引擎，与「当前会话」无关），另一个是围绕 `gift` 当前会话的运行时操作（io 收发、基址读写、gdb 交互、模式守卫）。这是内聚性问题——一个抽屉塞了太多东西。`cli_misc` 这个名字本身也是又一个 misc。

紧接在 misc.py 拆分之后处理它，是因为它的内聚性矛盾比 utils 目录是否分层更突出、更影响日常维护。

## 方案

按职责拆成三个模块，并把 cli_misc 改名为 current_session（顺手消除 misc 名字）：

| 模块 | 职责 | 规模 |
|------|------|------|
| `current_gadgets.py` | CurrentGadgets / CG / load_currentgadgets_background，gadget 搜索与 ROP 链构建 | ~745 行 |
| `current_gdb.py` | 操作当前调试会话的 gdb：启动/附加、heaptrace、运行时查询与控制 | ~430 行 |
| `current_session.py` | 操作当前会话 gift 的 io 收发缩写、段基址读写、模式守卫装饰器 | ~470 行 |

依赖方向：`current_gdb → current_session`（单向）；`current_gadgets`、`current_session` 各自独立。无环。

## API

公共 API 完全不变。`from pwncli import *` 导出符号数维持 513；原 cli_misc 的 62 个公共符号按归属分入三模块（gadgets 3 + gdb 18 + session 41），逐项核对一致。

## 改动文件

- 新增：`utils/current_gadgets.py`、`current_gdb.py`、`current_session.py`
- 删除：`utils/cli_misc.py`
- 改 import：`utils/__init__.py`、`utils/cli_decorates.py`、`commands/cmd_debug.py`、`commands/cmd_remote.py`
- 改测试：`tests/util_test/test_recent_features.py`（gdb 用例 import 与 monkeypatch 目标 `cli_misc.*` → `current_gdb.*`）

## 实现要点

一是守卫装饰器与 stop 作为会话基元。`@only_*`（only_debug/only_gdb/only_nogdb/only_remote/only_debug_or_remote）在原文件被 16 处使用，`stop` 被 gdb 块调用。把它们留在 current_session、由 current_gdb 单向 import，保证依赖无环——若放进 current_gdb，则 current_session 自身的 `@only_debug` 等会反向依赖 current_gdb 而成环。

二是切分用脚本而非手工，避免从 1687 行里手抄出错。脚本按「顶层符号名 → 目标模块」的映射切分，装饰器行自动吸附到其下的函数，块尾的顶格分隔注释剥除。原文件 gdb 函数物理上分散在两段（209–548 与 621–682），按函数名归类而非按连续行区间。

三是 heaptrace 的模块级全局变量（`_tmux_pane`、`_gnome_pid`、`_heaptrace_pid`）必须跟 heaptrace 函数一起进 current_gdb。这些是函数用 `global` 引用的状态，若留在 current_session，current_gdb 里的 `global _tmux_pane` 会指向不存在的全局。

四是 import 用 AST 自由名分析兜底。current_gdb 沿用原文件的 `from .gdb_helper import *`，pyflakes 无法检测其 undefined；用一个 AST 脚本把模块 import、模块内定义、gdb_helper.__all__、builtins 作为已知集合，确认函数体没有漏 import 的库符号（误报的 history/text/s 等均为嵌套函数参数）。

五是测试 monkeypatch 目标迁移。`test_recent_features.py` 的 `TestGdbHelpers` 通过 `cli_misc.<name>` 打桩 subprocess/os/time/stop/warn_ex/attach/_get_tmux_info/gdb_cmd 等，这些名字现都在 current_gdb 命名空间内（含它 import 进来的 stop/warn_ex/attach），全局替换为 current_gdb 即可。
