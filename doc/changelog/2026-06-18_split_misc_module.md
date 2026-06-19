# 拆解 utils/misc.py 为按职责命名的模块

## 动机

`pwncli/utils/misc.py` 累积到 1086 行，塞进了七八种互不相干的技术关注点：日志、进制转换、pack/unpack 增强、运行时地址接收、堆偏移计算、safe-linking、URL/Base64 编码、环境探测。`misc` 这个名字本身是反模式——它没有边界，新增内容不需要思考往哪放，长期必然膨胀成无人敢动的垃圾堆。

需要区分的是：这里的 misc 是「管理问题」而非「态度问题」。用黄金法则检验——删掉它，报红的是 `gift`、`errlog_exit`、`log_ex`、`u64_ex` 这些被全项目依赖的低层 PWN 原语，而非业务逻辑。这些函数本身是健康的基础设施，病根只在于一个大文件没有边界。因此治法是按技术维度拆进有名字的模块，而非否定它们。

## 方案

把 `misc.py` 按内聚性拆成 8 个有名字的模块，全部留在 `utils/` 扁平目录下（不做整体子包化），删除 `misc.py`，不保留兼容垫片。绝大多数用户写 `from pwncli import *`，公共 API 经 `utils/__init__.py` 重新导出后零影响。

| 新模块 | 职责 |
|--------|------|
| `state.py` | 共享状态总线 `gift` + 脚本模式初始化 `init_pwn_context` |
| `log.py` | 日志输出、地址打印、为日志服务的栈帧内省 |
| `packing.py` | 字节/数字打包解包、进制转换、浮点内存互转、填充 |
| `recv.py` | 运行时地址接收/解析 |
| `heapcalc.py` | house of corrosion / tcache 偏移 / safe-linking 纯算术 |
| `encoding.py` | URL 与 Base64 编码 |
| `onegadget.py` | one_gadget 与 libc 路径探测 |
| `env.py` | tmux/wsl/gdb 插件/ELF 架构探测，ctypes 与 signal 底层调用 |

## API

公共 API 完全不变。`from pwncli import *` 导出的符号数维持 513 个（拆分前后逐项核对一致）。脚本里 `gift`、`u64_ex`、`one_gadget`、`init_pwn_context` 等的用法不受影响。

唯一会断的是直接 `from pwncli.utils.misc import X` 的外部脚本——这种写法极少，按既定决策不兼容。

## 改动文件

- 新增：`utils/state.py`、`log.py`、`packing.py`、`recv.py`、`heapcalc.py`、`encoding.py`、`onegadget.py`、`env.py`
- 删除：`utils/misc.py`
- 改 import：`utils/__init__.py`、`cli.py`，以及 utils 内部 `bruteforce/gdb_helper/gadgetbox/libcbox/cli_decorates/decorates/cli_misc`，命令层 `cmd_initial/listen/tmux/misc/gadget/qemu/debug/patchelf/remote/template`
- 文档：`CLAUDE.md` 中 gift 定义位置由 `utils/misc.py` 改为 `utils/state.py`

## 实现要点

一是依赖分层无环。第 0 层（无内部依赖）：`log`、`heapcalc`、`encoding`、`env`；第 1 层：`packing`（→log）、`onegadget`（→log）、`state`（→env）；第 2 层：`recv`（→packing、log）。

二是 utils 内部模块之间一律用 `from .<模块> import ...` 直连，**绝不走 `from . import`**。因为 `utils/__init__.py` 在导入期会聚合所有子模块，内部若写 `from . import X` 会撞上半初始化的 `__init__`。

三是一个命名陷阱教训：承载共享状态实例的模块最初命名为 `gift.py`，与它导出的实例名 `gift` 冲突。`from .gift import *` 会把实例写进 `utils.gift` 属性、覆盖子模块对象，导致 `__init__.py` 里 `gift.__all__` 取到实例并经 `_Inner_Dict.__getattr__` 返回 `None`，抛 `TypeError: 'NoneType' object is not iterable`。改名为 `state.py` 后解决（这个名字也更贴合「共享状态总线」的定位）。模块名不得与其导出的同名对象重名。

四是私有符号（`_Inner_Dict`、`_in_tmux`、`_in_wsl`、`_get_gdb_plugin_info`、`_get_elf_arch_info`）不进任何 `__all__`，被命令层直接 import，因此命令层必须精确指向 `..utils.state` / `..utils.env`，无法走聚合导出。
