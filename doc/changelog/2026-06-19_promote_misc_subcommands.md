# 提升 misc 子命令为顶层：setgdb / dstruct / gadget

## 动机

`pwncli/commands/cmd_misc.py` 定义了一个 `misc` 命令组（"Misc of useful sub-commands"），含两个互不相干的子命令：`setgdb`（gdb 环境配置）与 `dstruct`（用 gdb 提取结构体）。这是 CLI 层的 misc 反模式——一个叫 misc 的杂物桶装着没有共同领域的子命令，与此前已清理的 `utils/misc.py`、`cli_misc.py` 同源。

关键先例：`gadget` 命令原本也是 misc 的子命令，后已提升为顶层（`cmd_gadget.py`）。README 的 `## misc 子命令` 段却仍把 gadget 列在 misc 下、且漏文档了 dstruct，说明 misc 一直在被逐步清空、文档也已欠债。本次把剩下的 setgdb/dstruct 提升为顶层、删除 misc 组，完成这个迁移。

## 方案

仿 `cmd_gadget.py` 的顶层命令模式，把两个子命令各独立成文件：

- 新增 `pwncli/commands/cmd_setgdb.py`：顶层 `setgdb` 命令，搬入原 `copy_gdbinit` 逻辑。
- 新增 `pwncli/commands/cmd_dstruct.py`：顶层 `dstruct` 命令，搬入原 `export_struct_info` 逻辑（含那段 gdb python 脚本字符串原样保留）。
- 删除 `pwncli/commands/cmd_misc.py`。
- 丢弃原文件中未使用的 `_Inner_Dict` import（两个子命令都不引用它）。
- 每个命令开头设 `ctx.verbose = 2`：原 misc 组回调强制 verbose=2，提升后由各命令自行设置以保留行为。

自动发现机制无需改动：`cli.py` 的 `CommandsAliasedGroup` 扫描 `commands/cmd_*.py`，新文件自动成为顶层命令。

## API

CLI 路径变化：`pwncli misc setgdb` → `pwncli setgdb`，`pwncli misc dstruct` → `pwncli dstruct`。这与既有的 `pwncli misc gadget` → `pwncli gadget` 迁移一致。`misc` 命令组消失。

前缀匹配影响：`dstruct` 与 `debug` 均以 `d` 开头，`pwncli d` 变歧义，需输 `pwncli ds` 或 `pwncli de`；`setgdb` 以 `s` 开头，唯一。

## 改动文件

- 新增：`pwncli/commands/cmd_setgdb.py`、`pwncli/commands/cmd_dstruct.py`
- 删除：`pwncli/commands/cmd_misc.py`
- `tests/cmd_test/test_pwncli.py`：把 `["misc", "setgdb", "dstruct"]` 拆为 `["setgdb"]` 与 `["dstruct"]` 两条
- `README.md`：重写 `## misc 子命令` 段为 `## gadget 子命令`、`## setgdb 子命令`、`## dstruct 子命令` 三个顶层小节；同步修正 TOC、命令树、命令列表、示例中所有 misc 引用（含过时的 `pwncli misc gadget` → `pwncli gadget`）

## 实现要点

两个新文件照搬原子命令的逻辑，仅调整装饰器从 `@cli.command(...)`（misc 组的子命令）改为 `@click.command(name=..., short_help=...)`（顶层命令），并补 `@pass_environ`。`ctx.verbose = 2` 这一处易漏——没有它，命令会因 verbose 默认 0 而静默，丢失原 misc 组强制的进度日志。

README 的命令清单本就存在较广的既有欠债（缺 initial/listen/template/tmux/update 等命令、残留已删除的 test 命令），本次只精准处理 misc 相关与 gadget 误嵌，不扩展到全量修订。

## 验证

`pwncli setgdb --help` 与 `pwncli dstruct --help` 退出 0；`pwncli misc --help` 失败（misc 已消失）；`pwncli --help` 列出 setgdb/dstruct、不含 misc；前缀 `ds`→dstruct、`de`→debug、`d` 歧义；`tests/cmd_test/test_pwncli.py` 通过。
