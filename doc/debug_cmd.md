

# pwncli debug 命令

`debug` 是我开发的第一个命令，也是我使用次数最多的一个命令，其主要用于本地调试。`debug` 命令支持的功能有：配合 `gdb` 调试程序和 `exp` 脚本；非常方便地下断点和执行 `gdb` 命令；`hook` 指定函数，可绕过反调试；设置 `env`（LD_PRELOAD），替换程序链接的 `so`；在 `main` 函数前停住，以命中断点。

接下来对 `debug` 命令做一个详细的说明和展示。文中所有示例都假设 `exp.py` 里调用了 `cli_script()`，即脚本模式；纯命令行模式（直接敲 `pwncli debug ./pwn`）的用法完全一致，只是把 `python3 exp.py debug` 换成 `pwncli debug`。

***

## 1 简单使用

最简单的调试只需要给出文件名：

```bash
python3 exp.py debug ./pwn
```

此时 `debug` 会用 pwntools 启动该进程，把 `io`、`elf`、`libc` 三个对象塞进全局的 `gift` 字典，脚本里直接取用即可：

```python
from pwncli import *
cli_script()

io = gift['io']      # 启动好的 process 对象
elf = gift['elf']    # ELF 对象
libc = gift['libc']  # 自动解析出的 libc（动态链接时）
```

常用的几个全局选项：`-a/--argv` 给进程传命令行参数；`-e/--env` 设置环境变量（详见第 6 节）；`-v/--verbose` 打开详细日志，调试 `debug` 命令本身的行为时很有用，可叠加多个 `-v`。

```bash
# 传入 argv，并打开详细日志
python3 exp.py debug ./pwn -a "arg1 arg2" -vv
```

***

## 2 配合 `gdb` 使用

光启动进程还不够，调试的核心是把 `gdb` 拉起来。`debug` 命令本身不决定 `gdb` 弹在哪里，它依赖一个“终端载体”，由下面几个选项二选一指定：

`-t/--tmux` 在 tmux 中横向分屏弹出 gdb，这是 Linux 下最顺手的方式，前提是你已经在 tmux 会话里；`-w/--wsl` 用于 WSL 环境，从 Windows 侧弹出窗口；`-g/--gnome` 用 gnome-terminal 弹窗。

```bash
# 在 tmux 里分屏调试（最常用）
python3 exp.py debug ./pwn -t

# WSL 环境弹窗
python3 exp.py debug ./pwn -w

# gnome-terminal 弹窗
python3 exp.py debug ./pwn -g
```

如果都不指定，又没有命中其它自动判定，则不会启动 gdb，只是单纯跑进程。加上 `-u/--use-gdb` 可以让 pwncli 尽量用 pwntools 的默认终端把 gdb 拉起来。

可见终端载体和 gdb 的启动是解耦的。`-m/--attach-mode` 进一步细化 WSL 下的弹窗方式，取值覆盖 `bash.exe`、`ubuntu1x04.exe`、`open-wsl.exe`、`wt.exe`、`wsl.exe` 等多种途径，默认 `auto` 会按当前环境自动挑一个；多数情况下不用手动指定。

### gdb 插件选择

`-G/--gdb-type` 用来切换 gdb 插件，支持 `pwndbg`、`gef`、`peda`，默认 `auto` 表示沿用你当前的 `~/.gdbinit`。

```bash
python3 exp.py debug ./pwn -t -G pwndbg
```

注意一点：指定非 `auto` 的插件时，pwncli 会临时替换 `~/.gdbinit`，调试结束后自动还原，不会污染你原本的配置。

### attach 模式与 debug 模式

`-M/--gdb-method` 决定底层用 `gdb.attach()` 还是 `gdb.debug()`，默认 `attach`。

`attach` 模式先用 pwntools 启动进程，再让 gdb 附加上去，这是默认行为；`debug` 模式则由 gdb 直接把进程拉起来并停在入口点（entry point），更容易在 `main` 上断下来，适合需要从一开始就单步的场景。

```bash
# debug 模式，停在入口，直接在 main 下断
python3 exp.py debug ./pwn -t -M debug -b main
```

***

## 3 调试时下断点

断点是 `debug` 命令里设计得最细致的部分。三个相关选项：`-b/-gb/--gdb-breakpoint` 设置普通断点，可多次出现；`-T/-tb/--gdb-tbreakpoint` 设置临时断点（命中一次后自动删除），同样可多次出现；`-s/-gs/--gdb-script` 直接喂 gdb 脚本，下面单独讲。

```bash
# 同时下多个断点：函数名、绝对地址都行
python3 exp.py debug ./pwn -t -b malloc -b 0x400789 -T main
```

断点的值支持多种写法，这是为了应对 PIE 开启后地址会变的情况。普通写法直接给符号名或绝对地址即可（如 `malloc`、`0x400789`）；带基址偏移的写法则用前缀区分基准。

针对程序自身 ELF 基址的偏移，下面这些前缀等价，都表示“ELF 基址加偏移”：`$rebase(off)`、`$_base(off)`、`base+off`、`bin+off`、`b+off`，以及最简写的 `+off`。

```bash
# PIE 程序，断在 ELF 基址 + 0x1234 处，下面几种写法等价
python3 exp.py debug ./pwn -t -b '$rebase(0x1234)'
python3 exp.py debug ./pwn -t -b 'base+0x1234'
python3 exp.py debug ./pwn -t -b '+0x1234'
```

针对 libc 基址的偏移用 `lb+` 前缀，表示“libc 基址加偏移”：

```bash
# 断在 libc 基址 + 0x4f322 处
python3 exp.py debug ./pwn -t -b 'lb+0x4f322'
```

还有一类是“符号加偏移”，直接在断点里写带加减号的表达式，pwncli 会自动在 libc 和 ELF 的符号表里查符号，算出实际地址：

```bash
# 在 system 符号往后 0x10 处下断，符号会自动从 libc/elf 解析
python3 exp.py debug ./pwn -t -b 'system+0x10'
```

可见 pwncli 在内部用 `##...##`、`###...###`、`####...####` 三层占位符分别标记 libc 基址偏移、ELF 基址偏移、符号偏移，最终在进程启动、基址确定后统一替换成真实地址。这套机制让你写 exp 时不必关心 PIE 是否开启，断点表达式照写即可。

### 用 `-s` 传 gdb 脚本

`-s/--gdb-script` 既能接收一段以 `;` 分隔的 gdb 命令，也能接收一个脚本文件路径。

```bash
# 直接给命令串，用 ; 分隔
python3 exp.py debug ./pwn -t -s 'b malloc; b free; c'

# 给一个 gdb 脚本文件
python3 exp.py debug ./pwn -t -s ./mydebug.gdb
```

有一点值得注意：命令串里以 `b ` 开头的行会被识别成断点，自动并入 `-b` 的处理流程，因此上面 `b malloc` 里的 `malloc` 同样支持前面讲的全部基址前缀语法。

***

## 4 其他 `gdb` 命令

除了下断点，`debug` 还把一组常用的 gdb 操作封装成了脚本模式下可直接调用的函数（详见 `cli_misc` 文档）。在 exp 脚本里，进程跑起来、gdb 附加之后，可以这样动态下断、执行命令：

```python
from pwncli import *
cli_script()
io = gift['io']

# 运行时执行任意 gdb 命令
execute_cmd_in_current_gdb("b *0x401234; c")

# PIE 程序按偏移下断（需 pwndbg）
set_current_pie_breakpoints(0x1234)

# 给 gdb 进程发信号、发 continue
send_signal2current_gdbprocess(2)
send_continue2current_gdbprocess()
```

如果要附加一个已经在运行的进程（不经由 `debug` 命令启动），用 `attach_existing_process`，它接受 pid 或进程名：

```python
attach_existing_process(1234, gdbscript="c")
attach_existing_process("pwn_binary", gdbscript="b *main\nc")
```

***

## 5 `hook` 函数

反调试、或者某些干扰调试的函数（如 `alarm`、`sleep`、`ptrace`），可以在调试时直接把它们“掏空”。`debug` 提供两种 hook 方式。

`-H/-HF/--hook-function` 直接在命令行指定要 hook 的函数名，可多次出现。被 hook 的函数会被替换成一个直接返回的空函数，默认返回 0：

```bash
# 让 alarm 和 ptrace 直接返回，绕过反调试
python3 exp.py debug ./pwn -t -H alarm -H ptrace
```

需要指定返回值时，用 `:` 或 `=` 跟在函数名后面：

```bash
# 让 ptrace 返回 0，让 getuid 返回 1000
python3 exp.py debug ./pwn -t -H 'ptrace:0' -H 'getuid=1000'
```

`-f/-hf/--hook-file` 则指定一个 `hook.c` 文件，你在里面写自定义的 hook 函数，灵活性更高：

```bash
python3 exp.py debug ./pwn -t -f ./hook.c
```

这里有一点必须注意：hook 文件里不要引入任何标准库头文件，所有 `#include` 语句都会被忽略。其底层原理是把这些函数编译成一个 `.so`，再通过 `LD_PRELOAD` 注入，因此只能写不依赖 libc 的纯函数。

***

## 6 设置 env 和 LD_PRELOAD

`-e/--set-env/--env` 用来给被调试进程设置环境变量。多个变量之间用 `,` 或 `;` 分隔，键值之间用 `:` 或 `=` 连接。

```bash
# 替换 libc，这是打 libc 题最常见的用法
python3 exp.py debug ./pwn -t --env 'LD_PRELOAD:./libc-2.27.so'

# 同时设置多个环境变量
python3 exp.py debug ./pwn -t -e 'LD_PRELOAD:./libc.so.6,FOO=bar'
```

关于 libc 解析有一点值得说明：当 `LD_PRELOAD` 里包含名字带 `libc` 的 so 时，pwncli 会优先把它当作题目 libc 解析，并据此计算 `libc` 的基址；否则回退到用 `ldd` 找程序链接的 libc。如果你把替换用的 libc 文件放进 `LD_PRELOAD`，记得文件名里带上 `libc`，最稳妥的是直接命名为 `libc.so.6`。

需要注意，前面第 5 节的 hook 功能也是通过 `LD_PRELOAD` 实现的。当你同时使用 hook 和自定义 env 时，pwncli 会把 hook 生成的 `.so` 追加到你的 `LD_PRELOAD` 之后，两者不冲突。

***

## 7 在 `main` 函数前停住

有时候断点设在很靠前的位置（比如刚进 `main`），但 attach 模式下进程已经跑起来了，可能还没等 gdb 附加上去就冲过了断点。`-p/--pause/--pause-before-main` 解决的就是这个问题。

```bash
python3 exp.py debug ./pwn -t -p -b main
```

它的原理是在程序里注入一个 constructor 函数，在 `main` 执行之前用一个 `read` 系统调用把进程卡住，等 gdb 附加完成、断点都设好之后，pwncli 自动往进程里送一个字符让它继续。如此一来，再靠前的断点也不会漏掉。

如果你用的是第 2 节讲的 `-M debug` 模式，则不太需要这个选项——gdb 直接把进程停在入口点，本身就早于 `main`。

***

## 8 其他调试技巧

### 8.1 使用 stop 函数

`stop`（别名 `S`）是脚本模式下的“断点”，它会打印调用处的模块、函数、行号以及本地进程 pid，然后等你按键继续。这在排查 exp 走到哪一步、或者想在某处暂停去 gdb 里看看时非常顺手。

```python
from pwncli import *
cli_script()
io = gift['io']

# ... 构造 payload ...
stop()            # 打印调用信息并暂停
io.send(payload)
S()               # S 是 stop 的别名
```

`-P/-ns/--no-stop` 可以全局禁用所有 `stop` 调用，这样不必逐个删掉 `stop()` 就能让脚本一路跑通，方便从调试切到打远程。

```bash
python3 exp.py debug ./pwn -P
```

### 8.2 去掉 pwntools 的 log 信息

调试稳定后，pwntools 那一大串 `[DEBUG]`、`[*]` 日志会显得很吵。`-n/-nl/--no-log` 把 `context.log_level` 直接拉到 `error`，只保留报错信息。

```bash
python3 exp.py debug ./pwn -n
```

到此 `debug` 命令的主要功能就讲完了。实战中最高频的组合，是 tmux 分屏配合若干断点，再按需叠加 libc 替换、hook 和 pause，绝大多数本地调试场景都能覆盖。
