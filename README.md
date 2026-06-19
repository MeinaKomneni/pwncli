- [前言](#前言)
- [简介](#简介)
- [安装](#安装)
- [使用模式](#使用模式)
  - [命令行模式](#命令行模式)
  - [脚本模式](#脚本模式)
  - [库模式](#库模式)
- [教程](#教程)
- [pwncli 主命令](#pwncli-主命令)
  - [debug 子命令](#debug-子命令)
  - [remote 子命令](#remote-子命令)
  - [config 子命令](#config-子命令)
    - [list 二级子命令](#list-二级子命令)
    - [set 二级子命令](#set-二级子命令)
  - [gadget 子命令](#gadget-子命令)
  - [setgdb 子命令](#setgdb-子命令)
  - [dstruct 子命令](#dstruct-子命令)
  - [patchelf 子命令](#patchelf-子命令)
  - [qemu 子命令](#qemu-子命令)
  - [template 子命令](#template-子命令)
  - [initial 子命令](#initial-子命令)
  - [listen 子命令](#listen-子命令)
  - [tmux 子命令](#tmux-子命令)
  - [update 子命令](#update-子命令)
- [依赖库](#依赖库)
- [截图示例](#截图示例)
    - [pwncli 示例](#pwncli-示例)
    - [debug 示例](#debug-示例)
    - [remote 示例](#remote-示例)
    - [config 示例](#config-示例)
    - [setgdb 示例](#setgdb-示例)
    - [patchelf 示例](#patchelf-示例)
    - [qemu 示例](#qemu-示例)

> [!NOTE]
> The [deepwiki](https://deepwiki.org/) of pwncli: <https://deepwiki.com/RoderickChan/pwncli>

# 前言

一开始写这个工具是因为在学习`pwn`的过程中，经常反复的去注释和取消注释`gdb.attach(xxx)`这样的语句，下不同断点的时候要不断地修改脚本，本地调通打远程的时候也要改脚本。

习惯命令行操作后，我设想能否设计一个命令行工具，能通过命令行参数去控制一些东西，避免在调试`pwn`题的时候重复地执行上面这些工作而只专注于编写解题脚本。当想法酝酿起来，自己便试着写下第一行代码，于是，`pwncli`就此诞生。

工具的目的在于实用性，我觉得`pwncli`满足实用性要求，在调试`pwn`题时能节省大量的时间。

如果你觉得`pwncli`好用，请介绍给周围的`pwner`。如果你还有任何疑问，请提交`issue`或联系我`roderickchan@foxmail.com`，我将非常乐意与你讨论交流。如果你有好的想法，或者发现新的`bug`，欢迎提交`pull requests`。

🏴🏴🏴 欢迎各位师傅关注我的个人博客，以下两个博客网站内容相同，互为备份。前者为`github page`，后者部署在国内阿里云服务器上。博客持续更新中~
- https://roderickchan.github.io
- https://www.roderickchan.cn

# 简介
[EN](https://github.com/RoderickChan/pwncli/blob/main/README-EN.md) | [ZH](https://github.com/RoderickChan/pwncli/blob/main/README.md) | [API](https://github.com/RoderickChan/pwncli/blob/main/API-DOC.md) | [VIDEO](https://www.youtube.com/watch?v=QFemxI3rnC8)

`pwncli`是一款简单、易用的`pwn`题调试与攻击工具，能提高你在`CTF`比赛中调试`pwn`题脚本的速度与效率。

`pwncli`可以帮助你快速编写`pwn`题攻击脚本，并实现本地调试和远程攻击的便捷切换。`pwncli`支持三种使用模式：  
- 命令行使用模式  
- 脚本内使用模式  
- 库导入使用模式 

以上三种模式分别简称为：命令行模式、脚本模式和库模式。其中，命令行模式与其他命令行工具(如`linux`下的`ls`、`tar`等命令)使用方式相同，可用于本地交互调试；脚本模式可将自己编写的`python`攻击脚本包装为命令行工具，然后调用子命令执行所需功能；库模式则只会调用一些便捷的工具函数，方便快速解题。

在下面的使用模式章节将会详细的阐述三种模式的使用方式与技巧。

`pwncli`设计为主命令-子命令模式(与`git`类似)，目前已拥有的(子)命令有：  
```
pwncli
    config
        list
        set
    debug
    dstruct
    gadget
    initial
    listen
    patchelf
    qemu
    remote
    setgdb
    template
    tmux
    update
```
其中，`pwncli`为主命令，`config/debug/dstruct/gadget/initial/listen/patchelf/qemu/remote/setgdb/template/tmux/update`等为一级子命令，`list/set`为隶属`config`的二级子命令。

`pwncli`支持命令的前缀匹配(与`gdb`的命令前缀匹配类似)，通常只需要给出命令的前缀即可成功调用该命令。即输入`pwncli debug ./pwn`、`pwncli de ./pwn`和`pwncli d ./pwn`的执行效果是完全一样的。但是，必须保证前缀不会匹配到两个或多个子命令，否则将会抛出`MatchError`的匹配错误。 

`pwncli`极易扩展。只需要在`pwncli/commands`目录下添加`cmd_xxx.py`，然后编写自己的子命令即可。`pwncli`会自动探测并加载子命令。例如，你想新增一个`magic`命令，你只需要：  
```
1. 在pwncli/commands目录下新增cmd_magic.py文件
2. 在cmd_magic.py内编写命令的执行逻辑
```
当需要移除该命令时，可以删除`cmd_magic`文件，或将其重命名为非`cmd_`开头即可。

`pwncli`依赖于[click](https://github.com/pallets/click) 和 [pwntools](https://github.com/Gallopsled/pwntools)。前者是一款优秀的命令行编写工具，后者是`pwner`普遍使用的攻击库。

总结`pwncli`的优点为：  
- 脚本只需编写一次，使用命令行控制本地调试与远程攻击
- 调试过程中方便设置断点与执行其他`gdb`命令
- 可轻松扩展并自定义子命令
- 内置许多有用的命令与函数

# 安装
`pwncli`可以在`linux`和`windows`下使用，但在`windows`下使用受限严重，如`debug`命令将无法使用，`remote`命令仅部分可用。`pwncli`只能在`python3`环境上使用，目前暂不考虑与`python2`兼容。

建议在`ubuntu`系统上使用`pwncli`，特别的，如果你了解`WSL`并选择使用`WSL`解答`pwn`题，`pwncli + WSL`将是一个极佳的选择。`debug`子命令为`WSL`系统设计了许多实用的参数，并实现了一些有趣的功能。

如果你选择使用`WSL`，那么，请尽量保证发行版的名字(distribution name)为默认的`Ubuntu-16.04/Ubuntu-18.04/Ubuntu-20.04/Ubuntu-22.04`。`debug`命令的某些选项与默认发行版名称联系紧密。  

`pwncli`的安装方式有两种，第一种是本地安装(**强烈建议使用此种方式安装**)：

```shell
git clone https://github.com/RoderickChan/pwncli.git
cd ./pwncli
pip3 install --editable .
```
安装结束后，别忘了将`pwncli`所在的路径添加到`PATH`环境变量，其路径一般为`~/.local/bin`。可以在家目录下的`.bashrc/.zshrc`文件中添加`export PATH=$PATH:/home/xxx/.local/bin`。

这种方式安装的好处是：当你需要`pwncli`保持更新时，只需要执行`git pull`即可使用最新版本的`pwncli`。


第二种安装方式是使用`pip3`安装：
```
pip3 install pwncli
```
这种方式安装的`pwncli`可能不是最新版本，会遇到一些已解决的`bug`。不过请相信我，我会及时将`pwncli`更新到`pypi`上去的。

安装结束后，执行`pwncli --version`，看到版本信息输出则代表安装成功。

# 使用模式
## 命令行模式
你可以将`pwncli`视为一个命令行工具，虽然其本质是一个`python`脚本。使用`pwncli -h`或者`pwncli --help`将会获取到命令行的使用指导。如果你想获取某个子命令的使用指导，如`debug`命令，输入`pwncli debug -h`即可。

## 脚本模式
除了将`pwncli`当作命令行工具使用外，你还可以将脚本封装为一个命令行工具，之后，就能像使用`pwncli`一样使用这个脚本。  
脚本模式的使用非常简单，如你的攻击脚本为`exp.py`，在脚本中写下：
```python
#!/usr/bin/env python3
from pwncli import *

cli_script() # 使用脚本模式必须调用这个函数
```

然后，在命令行输入`python3 exp.py -h`即可获得和命令行模式下`pwncli -h`一样的输出。特别的，如果你在脚本的第一行指定了解释器路径，那么你可以输入`./exp.py -h`而无需显式输入`python3`。

之后，你可以将`exp.py`当成`pwncli`，使用`pwncli`所拥有的各项命令与功能。

当然，你可以丰富你的脚本，使其实现更多功能，如使用`debug`和`remote`命令时，你可以在脚本后面继续添加：
```python
#!/usr/bin/env python3
from pwncli import *

cli_script() # 使用脚本模式必须显式调用这个函数

# 你能够从gift里面取到很多东西
io   = gift['io'] # process或remote对象
elf  = gift["elf"] # ELF对象，ELF("./pwn")
libc = gift.libc # ELF对象， ELF("./libc.so.6")

filename  = gift.filename # current filename
is_debug  = gift.debug # is debug or not 
is_remote = gift.remote # is remote or not
gdb_pid   = gift.gdb_pid # gdb pid if debug

# 有时候远程提供的libc与本地不一样，打靶机时替换libc为远程libc
if gift.remote:
    libc = ELF("./libc.so.6")
    gift['libc'] = libc

# 这里写下攻击函数等
# ......
io.interactive() # 与socket保持交互
```
熟悉`pwntools`的小伙伴对上面的脚本肯定不会陌生。从本质上来说，调用`cli_script()`后会解析命令行参数，之后将一些有用的数据放置在`gift`中。如你可以取出`io`，就是`pwntools`模块中的`process`或`remote`对象，并与其交互。

## 库模式
库模式，顾名思义，适用于你仅仅需要使用`pwncli`的一些函数或功能而不需要使用命令行解析参数的场景。你可以像使用其他`python`库一样使用`pwncli`，如在脚本中写下：

```python
from pwncli import *

# 这里写下脚本的其他内容
# 你可以使用pwncli中提供的使用接口
context.arch="amd64"
io = process("./pwn")

# 如你需要根据偏移搜索libc版本与其他函数
# 该功能与LibcSearcher类似，但不需要本地安装，需要联网使用
libc_box = LibcBox()
libc_box.add_symbol("system", 0x640)
libc_box.add_symbol("puts", 0x810)
libc_box.search(download_symbols=False, download_so=False, download_deb=True) # 是否下载到本地
read_offset = libc_box.dump("read")

# 根据pid获取程序的libc基地址
res = get_segment_base_addr_by_proc_maps(pid=10150)
libc_base = res['libc']
heap_base = get_current_heapbase_addr() # 仅用于本地调试

# 获取shellcode
cat_flag = ShellcodeMall.amd64.cat_flag
reverse_tcp = ShellcodeMall.amd64.reverse_tcp_connect(ip="127.0.0.1", port=10001)

# 使用一些便捷的装饰器
# 在调用该函数前休眠
@sleep_call_before(1)
def add():
    pass

# 若该函数10s内都没有运行结束，就会抛出异常
@bomber(10)
def del_():
  pass

# api不再使用
@unused()
def wtf():
  pass

# 搜索gadget
ropper_box = RopperBox()
ropper_box.add_file("libc", "libc.so.6", arch=RopperArchType.x86_64)
pop_rdi_ret = ropper_box.get_pop_rdi_ret()
leav_ret = ropper_box.search_gadget("leave; ret")

# 构造IO_FILE结构体
fake_file = IO_FILE_plus_struct()
fake_file.flags = 0xfbad1887
fake_file._mode = 1
fake_file.vtable = 0xdeadbeef
payload = bytes(fake_file)

# 替换payload
payload = "aaaabbbbcccc"
new_payload = payload_replace(payload, {4: "eeee"}) # aaaaeeeecccc


# 获取当前装载的libc的gadget
all_ogs = get_current_one_gadget_from_libc()


# 封装当前io的常用操作函数
# sendline
sl("data")
# sendafter
sa("\n", "data")


# 直接使用当前gadget
CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

pop_rdi_ret = CurrentGadgets.pop_rdi_ret()

execve_chain = CurrentGadgets.execve_chain(bin_sh_addr=0x11223344)

# pwncli中还有许多其他实用的接口
# ......

io.interactive()
```

不难发现，库模式与命令模式的使用区别：去掉`cli_script()`即可。需要注意，库模式下的脚本就是一个普通的`python`脚本，并不能解析命令行参数。

# 教程
视频教程如下：
[![pwncli tutorial](https://res.cloudinary.com/marcomontalbano/image/upload/v1674919945/video_to_markdown/images/youtube--QFemxI3rnC8-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://www.youtube.com/watch?v=QFemxI3rnC8 "pwncli tutorial")


`asciinema`版本教程依次如下：
- [pwncli tutorial (1)](https://asciinema.org/a/555250)
- [pwncli tutorial (2)](https://asciinema.org/a/555251)
- [pwncli tutorial (3)](https://asciinema.org/a/555252)
- [pwncli tutorial (4)](https://asciinema.org/a/555313)


[![asciicast](https://asciinema.org/a/555250.svg)](https://asciinema.org/a/555250)


[![asciicast](https://asciinema.org/a/555251.svg)](https://asciinema.org/a/555251) 

[![asciicast](https://asciinema.org/a/555252.svg)](https://asciinema.org/a/555252)


[![asciicast](https://asciinema.org/a/555313.svg)](https://asciinema.org/a/555313)


以下为简易的文字版教程。

在使用`pwncli`之前，建议掌握`gdb/tmux`的基本命令，确保已安装了`pwndbg/gef/peda`等其中一个或多个插件。

以脚本模式下的`debug`命令为例(这也是最常使用的模式和命令)。

首先进入`tmux`环境，使用`tmux new -s xxx`进入即可。

然后在脚本`exp.py`里写下：

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-

from pwncli import *

# use script mode
cli_script()

# get use for obj from gift
io: tube = gift['io'] 
elf: ELF = gift['elf']
libc: ELF = gift['libc']

ia()
```

然后赋予脚本执行权限，然后输入`./exp.py de ./pwn -t`即可看到开启了`tmux`调试窗口。

对于无`PIE`的程序，下断点的方式为：

```shell
./exp.py de ./pwn -t -b 0x400088a # 在0x400088a处下断点

./exp.py de ./pwn -t -b malloc -b free # 下2个断点
```

对于有`PIE`的程序，下断点的方式为：

```shell
./exp.py de ./pwn -t -b b+0xafd # 在 0xafd处下断点

./exp.py de ./pwn -t -b malloc -b free -b b+0x101f # 下3个断点

./exp.py de ./pwn -t -b malloc+0x10 # 在malloc+0x10处下断点，首先在libc里面寻找malloc符号，然后在elf中寻找malloc符号
```

想要`hook`掉某些函数，如`ptrace`：

```shell
./exp.py de ./pwn -H ptrace -H alarm:1   # hook掉ptrace，默认返回0；hook掉alarm，返回值为1

./exp.py de ./pwn -h ./hook.c # 自己写好hook.c后指定即可
```

使用带桌面的`ubuntu`虚拟机调试，可以选择`gnome`弹出窗口：

```shell
./exp.py de ./pwn -g -b 0x400088a # 在0x400088a处下断点

./exp.py de ./pwn -g -s "directory /usr/glibc/glibc-2.31/malloc" # 指定源码调试目录
```


脚本调试好后需要打远程：

```
./exp.py re ./pwn 127.0.0.1:13337
```


# pwncli 主命令
选项的相关说明：

- `flag`选项：带上该选项即为开启，如`ls -a`中的`-a`即为`flag`选项
- 多选的：可以指定多个值，如`-x y1 -x y2`可以传递`y1`和`y2`给`x`选项
- 多种使用方式：如`-x --xxx --xxx-xx`，那么使用`-x`或者`--xxx`或者`--xxx-xxx`均可



`pwncli`命令为主命令，输入`pwncli -h`将得到以下输出：

```
Usage: pwncli [OPTIONS] COMMAND [ARGS]...

  pwncli —— 面向 pwner 的工具！

  CLI 用法：
      pwncli -v subcommand args
  Python 脚本用法：
      脚本内容：
          from pwncli import *
          cli_script()
      然后从命令行启动：
          ./yourownscript -v subcommand args

Options:
  -f, --filename TEXT         Elf file path to pwn.
  -v, --verbose               Show more info or not.
  -E, -ea, --extra-argv TEXT  The extra argv for this script, sometimes it's
                              useful for bruteforce.  [default: ""]
  -V, --version               Show the version and exit.
  -h, --help                  Show this message and exit.

Commands:
  config    Get or set something about config data.
  debug     Debug the pwn file locally.
  dstruct   Display struct info by gdb.
  example   Example command.
  gadget    Get all gadgets using ropper and ROPgadget, and then store them in
            files.
  initial   pwn initial tool, inspired by https://github.com/io12/pwninit.
  listen    Listen on a port and spawn a program when connected.
  patchelf  Patchelf executable file with glibc-all-in-one.
  qemu      Use qemu to debug pwn, for kernel pwn or arm/mips arch.
  remote    Pwn remote host.
  setgdb    Copy gdbinit files from and set gdb-scripts for current user.
  template  Generate template file by pwncli.
  tmux      Use tmux to execuate command many times.
  update    Update pwncli.
```

**选项**：

```
-f  可选的  待调试的pwn文件路径，如./pwn，在这里指定后，debug/remote子命令中可无需指定。
-v  可选的  flag选项，默认关闭。开启后将显示log信息，如果需要显示更多信息，可以输入-vv。
-E  可选的  传递给脚本的额外参数，爆破场景下偶尔有用，默认为空字符串。
-V         查看版本信息。
-h         查看帮助。
```

**命令**(即`pwncli`下拥有的子命令)：

```
config     操作pwncli配置文件，配置文件路径为~/.pwncli.conf。
debug      最常用的子命令，用于本地调试pwn题。
dstruct    通过gdb提取并展示二进制文件中的结构体信息。
example    示例命令，演示如何编写子命令，无实际用途。
gadget     使用ropper和ROPgadget工具获取所有的gadgets，并将其存储在本地。
initial    受pwninit启发的初始化工具，自动补齐文件、解压、patchelf等。
listen     监听端口，连接到达后拉起指定程序，便于本地起题。
patchelf   快速地执行patchelf，以用于调试不同版本的glibc。
qemu       使用qemu调试pwn题，用于kernel pwn或其他架构的pwn。
remote     最常用的子命令，用于远程攻击靶机。
setgdb     将pwncli/conf/.gdbinit-xxx的配置文件拷贝到家目录。
template   生成各类攻击模板脚本。
tmux       利用tmux在多个pane/window中重复执行命令，便于爆破。
update     执行git pull更新pwncli。
```

## debug 子命令
输入`pwncli debug -h`将得到以下帮助文档：

```
Usage: pwncli debug [OPTIONS] [FILENAME]

  FILENAME: ELF 文件路径。

  CLI 模式：
      pwncli debug ./pwn -t -b malloc -gb 0x400789
      pwncli debug ./pwn -t --env LD_PRELOAD:./libc-2.27.so
      pwncli debug ./pwn -t -M debug -b main
  脚本模式：
      python3 exp.py debug ./pwn -t -b malloc

Options:
  -a, --argv TEXT                 Argv for process.
  -e, --set-env, --env TEXT       The env setting for process, such as
                                  LD_PRELOAD setting, split using ',' or ';',
                                  assign using ':'.
  -p, --pause, --pause-before-main
                                  Pause before main is called or not, which is
                                  helpful for gdb attach.
  -f, -hf, --hook-file TEXT       Specify a hook.c file, where you write some
                                  functions to hook.
  -H, -HF, --hook-function TEXT   The functions you want to hook would be out
                                  of work.
  -t, --use-tmux, --tmux          Use tmux to gdb-debug or not.
  -w, --use-wsl, --wsl            Use wsl to pop up windows for gdb-debug or
                                  not.
  -g, --use-gnome, --gnome        Use gnome terminal to pop up windows for
                                  gdb-debug or not.
  -m, -am, --attach-mode [auto|tmux|wsl-b|wsl-u|wsl-o|wsl-wt|wsl-wts|wsl-w|a|t|w|wt|wts|b|o|u]
                                  Gdb attach mode, wsl: bash.exe | wsl:
                                  ubuntu1x04.exe | wsl: open-wsl.exe | wsl:
                                  wt.exe wsl.exe  [default: auto]
  -u, -ug, --use-gdb              Use gdb possibly.
  -G, -gt, --gdb-type [auto|pwndbg|gef|peda]
                                  Select a gdb plugin.
  -b, -gb, --gdb-breakpoint TEXT  Set gdb breakpoints while gdb is used.
                                  Multiple breakpoints are supported.
  -T, -tb, --gdb-tbreakpoint TEXT
                                  Set gdb temporary breakpoints while gdb is
                                  used. Multiple tbreakpoints are supported.
  -s, -gs, --gdb-script TEXT      Set gdb commands like '-ex' or '-x' while
                                  gdb-debug is used, the content will be
                                  passed to gdb and use ';' to split lines.
                                  Besides eval-commands, file path is
                                  supported.
  -n, -nl, --no-log               Disable context.log or not.
  -P, -ns, --no-stop              Use the 'stop' function or not. Only for
                                  python script mode.
  -M, --gdb-method [attach|debug]
                                  Use gdb.attach() or gdb.debug(). 'debug'
                                  lets gdb start the process, stopping at
                                  entry — easier to break on main.  [default:
                                  attach]
  -v, --verbose                   Show more info or not.
  -h, --help                      Show this message and exit.
```

`debug`子命令是最常用的子命令，为其设计的参数也最多，下面将详细讲述每一个参数的意义和使用方式。

**参数**：

```
FILENAME  可选的  本地调试的pwn文件路径，还可以在pwncli主命令中通过-f选项设置；如pwncli主命令未设置，此处必须设置。
```

**选项**：

```
-a		可选的		除文件路径外，传递给process构造函数的参数。
-e		可选的		设置启动的环境变量，如LD_PRELOAD:./libc.so.6;PORT_ENV:1234,IP_ADDR=localhost，数据将传递给process构造函数的env参数。环境变量会统一转换为大写。LD_PRELOAD可以简写为PRE:./libc.so.6。
-p		可选的		flag选项，开启gdb后生效，默认关闭。开启后将在main函数之前卡住进程，方便gdb attach上去调试，避免有时候gdb.attach失败的问题。本质上是编译生成一个so文件，并将其设置为LD_PRELOAD环境变量，在init段执行一个read系统调用阻塞。
-f		可选的		开启gdb后生效，自己定义的hook.c文件，该文件会被编译为so，并设置为LD_PRELOAD环境变量。
-H		可选的		多选的，开启gdb后生效。选择要hook的函数名，如alarm函数，被hook的函数将直接返回0，支持多个选项，即可以 -H alarm -H ptrace。需要指定返回值时用:或=跟在函数名后，如 -H ptrace:0 -H getuid=1000。
-t		可选的		flag选项，默认关闭。开启后使用tmux开启gdb，并使用竖屏分屏。开启前必须保证在tmux环境中，否则会报错。
-w		可选的		flag选项，默认关闭。开启后使用wsl模式开启gdb，弹窗口调试。开启前必须保证在wsl的发行版环境中，否则会报错。
-g		可选的		flag选项，默认关闭。开启后使用gnome-terminal弹窗调试。
-m		可选的		开启gdb后生效，默认为auto。指定开启gdb的调试模式。auto：自动选择；tmux：开启-t后生效；wsl-b：开启-w后生效，使用bash.exe弹窗；wsl-u：开启-w后生效，使用ubuntu1x04.exe弹窗，前提是将其加入到windows宿主机的PATH环境变量中；wsl-o：开启-w后生效，使用open-wsl.exe弹窗，须到https://github.com/mskyaxl/wsl-terminal下载并将其加入到windows的PATH环境变量中；wsl-wt：开启-w后生效，使用windows-terminal弹窗，需安装windows terminal；wsl-wts：开启-w后生效，使用windows terminal分屏调试，需保证其版本至少为1.11.3471.0。
-u		可选的		flag选项，默认关闭。开启后会尽可能的使用gdb调试。
-G		可选的		开启gdb后生效，默认为auto。选择gdb插件类型。使用的前提是将gef、peda、pwndbg均安装在家目录下。auto：使用~/.gdbinit的配置，否则使用pwncli/conf/.gdbinit-xxx的配置。指定非auto插件时会临时替换~/.gdbinit，调试结束自动还原。
-b		可选的		多选的，开启gdb后生效。在gdb中设置断点。支持函数地址（-b 0x401020）、函数名（-b malloc）、PIE基址偏移（-b base+0x4f0 / -b b+0x4f0 / -b $rebase(0x4f0) / -b +0x4f0）、libc基址偏移（-b lb+0x4f322）以及符号加偏移（-b system+0x10）等多种写法。可设置多个断点，如-b malloc -b 0x401020。
-T		可选的		多选的，开启gdb后生效。设置临时断点，命中一次后自动删除，写法与-b一致。
-s		可选的		开启gdb后生效。可以是文件路径或者语句。如果是语句，设置后将在gdb中执行，每个子语句之间使用分号;分割，如-s "directory /usr/src/glibc/glibc-2.27/malloc;b malloc";如果是文件路径，则会在gdb中依次执行文件内的每一行语句。命令串里以b 开头的行会被识别成断点，并入-b处理流程，因此同样支持上述基址前缀语法。
-n		可选的		flag选项，默认关闭。设置pwntools为无log信息。若开启该选项，则会关闭pwntools的log。
-P		可选的		flag选项，默认关闭。设置stop函数失效。stop函数会等待输入并打印出当前信息，方便gdb调试。开启此选项后stop函数将失效。
-M		可选的		默认为attach。决定底层使用gdb.attach()还是gdb.debug()。attach：先启动进程再让gdb附加，为默认行为；debug：由gdb直接拉起进程并停在入口点，更容易在main上断下来。
-v		可选的		flag选项，默认关闭。开启后将显示log信息，如果需要显示更多信息，可以输入-vv。
-h		可选的		查看帮助。
```



## remote 子命令

输入`pwncli remote -h`得到以下帮助：

```
Usage: pwncli remote [OPTIONS] [FILENAME] [TARGET] [TPORT]

  FILENAME: ELF 文件路径。

  TARGET: 目标主机。

  远程目标示例：
      pwncli -v remote ./pwn 127.0.0.1:23333 -up --proxy-mode default
  或者显式指定 ip 与端口：
      pwncli -v remote -i 127.0.0.1 -p 23333

Options:
  -i, --ip TEXT                   The remote ip addr.
  -p, --port INTEGER              The remote port.
  -P, -up, --use-proxy            Use proxy or not.
  -m, -pm, --proxy-mode [undefined|notset|default|primitive]
                                  Set proxy mode. undefined: read proxy data
                                  from config data(do not set this type in
                                  your file); notset: not use proxy; default:
                                  pwntools context proxy; primitive: pure
                                  socks connection proxy.  [default:
                                  undefined]
  -n, -nl, --no-log               Disable context.log or not.
  -v, --verbose                   Show more info or not.
  -h, --help                      Show this message and exit.
```

`remote`也是使用较多的子命令，用于远程攻击靶机。在本地调试好脚本后，只需要将`debug`命令替换为`remote`，并设置参数，即可开始攻击靶机，不需要更改脚本。

**参数**：

```
FILENAME	可选的		本地调试的pwn文件路径，还可以在pwncli主命令中通过-f选项设置；设置后将不需要手动设置context.arch、context.os等信息。
TARGET		可选的		目标靶机；如果不用-i和-p参数，则必须指定。格式为：ip:port，如127.0.0.1:1234。
TPORT		可选的		目标靶机端口；当TARGET未带端口时可单独给出，等价于-p。
```

**选项**：

```
-i		可选的		设置目标靶机，可为域名或ip地址。若TARGET参数中未设置，则此处必须设置。若~/.pwncli.conf中有配置，则将读取配置文件中的目标ip地址为默认值。
-p		可选的		设置目标靶机的端口。若TARGET参数未设置，则此处必须设置。
-P		可选的		flag选项，默认关闭。开启后将使用代理。
-m		可选的		开启代理后生效。将会从~/.pwncli.conf中读取代理配置。undefined：未定义代理；notset：不使用代理；default：使用pwntools的context.proxy设置；primitive：使用socks设置。
-n		可选的		flag选项，默认关闭。设置pwntools为无log信息。若开启该选项，则会关闭pwntools的log。
-v		可选的		flag选项，默认关闭。开启后将显示log信息，如果需要显示更多信息，可以输入-vv。
-h         		  查看帮助。
```

## config 子命令

`config`子命令主要用于操作`pwncli`的配置文件，配置文件的路径为`~/.pwncli.conf`,其指导为：

```
Usage: pwncli config [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  list  List config data.
  set   Set config data.
```

**选项**：

```
-h		查看帮助。
```

**命令**：

```
list	查看配置文件数据。
set		设置配置文件数据。
```

### list 二级子命令

输入`pwncli config list -h`获得如下输出：

```
Usage: pwncli config list [OPTIONS] [LISTDATA]

  LISTDATA: List all data or example data or section names.

Options:
  -s, -sn, --section-name TEXT  List config data by section name.
  -h, --help                    Show this message and exit.
```

**参数**：

```
LISTDATA	可选的		列出的数据类型。all：列出配置文件所有数据；example：列出示例的配置文件数据；section：列出配置文件中数据的section；其他值为非法值。
```

**选项**：

```
-s		可选的		多选的。根据section的名字列出数据。
-h         		  查看帮助。
```

### set 二级子命令

输入`pwncli config set -h`获得如下输出：

```
Usage: pwncli config set [OPTIONS] [CLAUSE]

Options:
  -s, -sn, --section-name TEXT  Set config data by section name.
  -h, --help                    Show this message and exit.
```

**参数**：

```
CLAUSE	必须的		设置的语句，格式为key=value。
```

**选项**：

```
-s		可选的		根据section设置数据。
-h         		  查看帮助。
```

## gadget 子命令

使用ropper和ROPgadget工具获取所有的gadgets，并将其存储在本地。

输出`pwncli gadget -h`得到帮助信息：

```
Usage: pwncli gadget [OPTIONS] [FILENAME]

  FILENAME: 二进制文件名。

  pwncli gadget ./pwn -d ./gadgets -a -n 20
  pwncli gadget ./pwn -x 015dc3

  pwncli g ./pwn -n 10

Options:
  -a, --all, --all-gadgets      Get all gadgets and don't remove duplicates.
  -d, --dir, --directory PATH   The directory to save files.
  -x, --opcode TEXT             The opcode mode.
  -n, --depth, --count INTEGER  The depth of the gadgets.
  -v, --verbose                 Show more info or not.
  -h, --help                    Show this message and exit.
```

**参数**：

```
FILENAME	可选的		要获取gadgets的binary路径。
```

**选项**：

```
-a		可选的		flag选项，默认关闭。开启后将不会移除重复的gadgets。
-d		可选的		保存gadgets文件的路径。若未指定则为当前目录。
-x		可选的		opcode模式，直接按opcode搜索，如-x 015dc3。
-n		可选的		搜索gadget的深度/数量。
-v		可选的		flag选项，开启后显示更多日志。
-h		查看帮助。
```

## setgdb 子命令

将pwncli/conf/.gdbinit-xxx的配置文件拷贝到家目录。使用该命令的前提是将gef、peda、pwndbg、Pwbgdb插件下载到家目录。

输入`pwncli setgdb -h`得到帮助信息：

```
Usage: pwncli setgdb [OPTIONS]

Options:
  -g, --generate-script  Generate the scripts of gdb-gef/gdb-pwndbg/gdb-peda
                         in /bin or $HOME/.local/bin or not.
  --yes                  Confirm the action without prompting.
  -h, --help             Show this message and exit.
```

**选项**：

```
-g		可选的		flag选项，默认关闭。开启后将在/bin或$HOME/.local/bin下生成三个shell脚本,gdb-gef、gdb-peda、gdb-pwndbg。该选项需要在sudo下使用。
--yes	确认项		输入y后该命令生效。
-h		查看帮助。
```

其中`gdb-pwndbg`的内容为：

```
#!/bin/sh
cp ~/.gdbinit-pwndbg ~/.gdbinit
exec gdb "$@"
```

## dstruct 子命令

通过gdb提取并展示二进制文件中的结构体信息。

输入`pwncli dstruct -h`得到帮助信息：

```
Usage: pwncli dstruct [OPTIONS] [FILENAME]

Options:
  -s, --save-all               Save all struct info or not.
  -d, --dir, --directory PATH  The directory to save files.
  -n, --name TEXT              The name of struct you want to show.
  -h, --help                   Show this message and exit.
```

**参数**：

```
FILENAME	可选的		要提取结构体信息的binary路径。
```

**选项**：

```
-s		可选的		flag选项，默认关闭。开启后将把全部结构体信息保存到文件。
-d		可选的		保存文件的目录。若未指定则为当前目录。
-n		可选的		可多次指定，指定要展示的结构体名。未指定时交互确认后展示全部。
-h		查看帮助。
```

## patchelf 子命令

使用`patchelf`修改二进制文件使用的`libc.so.6`和`ld.so`。使用该命令的前提是，已安装`patchelf`和`glibc-all-in-one`，并将各个版本的库文件放置在`glibc-all-in-one/libs`，该路径可在配置文件中配置。

输入`pwncli patchelf -h`得到帮助信息：

```
Usage: pwncli patchelf [OPTIONS] FILENAME [LIBC_VERSION]

  FILENAME: ELF 可执行文件路径。

  LIBC_VERSION: libc 版本。

  pwncli patchelf ./filename 2.23 -b

  实际执行：

      patchelf --set-interpreter ./ld-2.23.so ./pwn

      patchelf --replace-needed libc.so.6 ./libc-2.23.so ./pwn

Options:
  -b, --back, --back-up           Backup target file or not.
  -f, --filter, --filter-string TEXT
                                  Add filter condition.
  -s, -l, --libc-so PATH          The libc.so.6 file, libc_version will be
                                  ignored when libc.so.6 file specified.
  -v, --verbose                   Show more info or not.
  -h, --help                      Show this message and exit.
```

**参数**：

```
FILENAME		必须的		待patch的文件路径。
LIBC_VERSION	可选的		libc版本，如2.23。指定-s/--libc-so直接给出libc文件时该项将被忽略。
```

**选项**：

```
-b		可选的		flag选项，默认关闭。开启后将备份一份文件后再执行patchelf命令，建议开启。
-f		可选的		过滤器，设置过滤条件。如-f 2.23，则会匹配到2.23版本的glibc库。
-s		可选的		直接指定libc.so.6文件路径，给出后LIBC_VERSION被忽略，同时会尝试在同目录寻找对应的ld。
-v		可选的		flag选项，开启后显示更多日志。
-h		查看帮助。
```

## qemu 子命令

该子命令方便使用`qemu`进行其他架构`arm/mips`文件的调试以及`kernel pwn`的调试。该命令的使用与`debug`子命令非常类似，很多选项与参数与`debug`子命令相同，使用方法也是一样的。在使用该子命令之前，请确保已安装了`qemu`和所需依赖库。

输入`pwncli qemu -h`得到帮助信息：

```
Usage: pwncli qemu [OPTIONS] [FILENAME] [TARGET]

  FILENAME: The binary file name.

  TARGET:  remote_ip:remote_port.

  Debug mode is default setting, debug with qemu:
      pwncli qemu ./pwn -S --tmux
      pwncli qemu ./pwn -L ./libs --tmux
  Specify qemu gdb listen port: 
      pwncli qemu ./pwn -L ./libs -S -p 1235
  Attack remote:
      pwncli qemu ./pwn 127.0.0.1:10001
      pwncli qemu ./pwn -r -i 127.0.0.1 -p 10001

Options:
  -a, --arch TEXT                 The arch for current file.
  -d, --debug, --debug-mode       Use debug mode or not, default is opened.
  -r, --remote, --remote-mode     Use remote mode or not, default is debug
                                  mode.  [default: False]
  -i, --ip TEXT                   The remote ip addr or gdb listen ip when
                                  debug.
  -p, --port INTEGER              The remote port or gdb listen port when
                                  debug.
  -L, --lib TEXT                  The lib path for current file.
  -S, --static                    Use tmux to gdb-debug or not.  [default:
                                  False]
  -l, -ls, --launch-script TEXT   The script to launch the qemu, only used for
                                  qemu-system mode and the script must be
                                  shell script.
  -t, --use-tmux, --tmux          Use tmux to gdb-debug or not.  [default:
                                  False]
  -w, --use-wsl, --wsl            Use wsl to pop up windows for gdb-debug or
                                  not.  [default: False]
  -g, --use-gnome, --gnome        Use gnome terminal to pop up windows for
                                  gdb-debug or not.  [default: False]
  -G, -gt, --gdb-type [auto|pwndbg|gef|peda]
                                  Select a gdb plugin.
  -b, -gb, --gdb-breakpoint TEXT  Set gdb breakpoints while gdb-debug is used,
                                  it should be a hex address or a function
                                  name. Multiple breakpoints are supported.
  -s, -gs, --gdb-script TEXT      Set gdb commands like '-ex' or '-x' while
                                  gdb-debug is used, the content will be
                                  passed to gdb and use ';' to split lines.
                                  Besides eval-commands, file path is
                                  supported.
  -n, -nl, --no-log               Disable context.log or not.  [default:
                                  False]
  -P, -ns, --no-stop              Use the 'stop' function or not. Only for
                                  python script mode.  [default: False]
  -v, --verbose                   Show more info or not.  [default: 0]
  -h, --help                      Show this message and exit.
```

**参数**：

```
FILENAME    可选的    调试的binary文件路径，kernel pwn可以是ko
TARGET      可选的    远程攻击时的ip和port，FILENAME和TARGET必须指定一个
```

**选项**：

```
-a    可选的    指定当前文件的架构，如arm/mips等，会传递给qemu和gdb-multiarch。
-d    可选的    flag选项，默认开启。该选项一般不需要显示指定。
-r    可选的    flag选项，默认关闭。可显示指定，表明此时为攻击远程。 
-i    可选的    在remote mode下为靶机ip地址；在debug mode下为gdb的监听ip地址。 
-p    可选的    在remote mde下为靶机端口；在debug mode下为gdb的监听端口。 
-L    可选的    在qemu-user下的动态链接库目录，会传递给qemu，若未指定，则会到/usr目录下寻找 
-S    可选的    flag选项，默认关闭。开启后将使用qemu-xxxx-static。 
-l    可选的    qemu启动的脚本路径，方便kernel pwn调试。 
-t    可选的    flag选项，默认关闭。开启后使用tmux开启gdb-multiarch调试。
-w    可选的    flag选项，默认关闭。开启后使用wsl调试。 
-g    可选的    flag选项，默认关闭。开启后使用gnome-terminal调试。 
-G    可选的    显示指定本次调试使用的gdb插件，pwndbg/peda/gef。 
-b    可选的    设置断点，与debug子命令的设置方式类似，但是不支持PIE类的断点。 
-s    可选的    设置gdb的命令，与debug子命令的设置方式类似，支持语句或文件路径。 
-n    可选的    flag选项，默认关闭。开启后将设置pwntools的日志级别为error。 
-P    可选的    flag选项，默认关闭。开启后使stop函数失效。 

```

## template 子命令

该子命令方便生成各种攻击模板脚本文件，包括使用`pwncli`的命令行模式与脚本模式的攻击脚本，同时还提供了使用原生的`pwntools`需要使用到的模板。模板中定义了本地调试与远程攻击的相关代码，提供了常用的缩写函数，如`sa/sla/r/rl`等。

输入`pwncli template -h` 得到帮助信息：

```
Usage: pwncli template [OPTIONS] [FILETYPE]

  FILETYPE: The type of exp file

  pwncli template cli
  pwncli template lib
  pwncli template pwn

Options:
  -h, --help  Show this message and exit.
```

其中，`cli`类型模板会使用`pwncli`的脚本模式，`lib`类型模板会使用库模式，`pwn`类型模板直接使用原始的`pwntools`来构建而不会使用`pwncli`。

## initial 子命令

受 [pwninit](https://github.com/io12/pwninit) 启发的题目初始化工具，在当前目录下自动完成补齐全套文件、解压、`patchelf`等一揽子工作，省去手工准备环境的麻烦。直接在题目所在目录执行即可：

```shell
pwncli initial
```

命令会扫描当前目录下的二进制与压缩包，识别架构与libc，自动解压并列出缺失的`libc.so.6`/`ld.so`，必要时调用`patchelf`完成替换。该命令目前不带额外选项，行为完全自动。

## listen 子命令

在本地监听一个端口，连接到达后拉起指定程序，便于本地起题或模拟远程环境。配合`debug`命令调试本地起的题目时尤为顺手。

输入`pwncli listen -h`得到帮助信息：

```
Usage: pwncli listen [OPTIONS]

  pwncli listen -l
  pwncli listen -L
  pwncli listen -l -p 10001
  pwncli listen -l -vv -p 10001
  pwncli listen -l -vv -p 10001 -e /bin/bash # socat tcp-l:10001,fork exec:/bin/bash

  pwncli l -l

Options:
  -l, --listen-once      List once.
  -L, --listen-forever   List forever.
  -p, --port INTEGER     List port.
  -t, --timeout INTEGER  List port.
  -e, --executable TEXT  Executable file path to spawn.
  -v, --verbose          Show more info or not.
  -h, --help             Show this message and exit.
```

**选项**：

```
-l		可选的		flag选项，监听一次后退出。
-L		可选的		flag选项，持续监听，每次连接到达都拉起程序。
-p		可选的		监听端口。
-t		可选的		超时时间。
-e		可选的		连接到达后拉起的可执行文件路径，如/bin/bash。
-v		可选的		flag选项，开启后显示更多日志。
-h		查看帮助。
```

底层等价于`socat tcp-l:PORT,fork exec:EXECUTABLE`，因此`-e /bin/bash`即可得到一个交互式shell端口。

## tmux 子命令

利用`tmux`在多个pane/window中重复执行同一条命令，爆破、批量打靶机时免开一堆终端。命令可重复指定，按`-c ... -t N`分组。

输入`pwncli tmux -h`得到帮助信息：

```
Usage: pwncli tmux [OPTIONS]

  使用 tmux 执行命令。

  例如：pwncli tmux -c "python3 ./exp.py re ./pwn 127.0.0.1 13337" -t 4 -p 4

  在四个窗口中执行 'ls -alh'：
      pwncli tmux -c "ls -alh" -t 4
  执行 'ls -al' 三次，每个 pane 执行一条命令，三个 pane 合为一个 window：
      pwncli tmux -c "ls -al" -t 3 -p 3
      pwncli tmux -c "ls -al" -t 3 -p 1 # 每个 window 一个 pane
  执行 'ls -al' 两次、'date' 三次，每个 pane 执行一条命令，四个 pane 合为一个 window：
      pwncli tmux -c "ls -alh" -t 2 -c "date" -t 3 -p 4

Options:
  -c, --cmd, --command TEXT       The commands you want to execuate.
  -t, --times INTEGER             The times of commands that you want to
                                  repeat.
  -p, --panes-per-window INTEGER RANGE
                                  The number of panes in each window.
                                  [default: 1; 1<x<=8]
  -T, --timeout INTEGER           Close the session when timeout, -1 means no
                                  timeout.
  -s, --save, --save-output       Save output for panes.
  -a, --attach, --attach-session  Attach session or not
  -k, --kill, --kill-after-detach
                                  Kill session after detach.
  -v, --verbose                   Show more info or not.  [default: 0]
  -h, --help                      Show this message and exit.
```

**选项**：

```
-c		可选的		多选的。要执行的命令，可与-t配对多次指定，实现不同命令各重复若干次。
-t		可选的		紧随其后的-c命令重复执行的次数。
-p		可选的		每个window中的pane数量，取值1~8，默认1。
-T		可选的		超时后关闭session，-1表示不超时。
-s		可选的		flag选项，保存各pane的输出。
-a		可选的		flag选项，创建后 attach 到该 session。
-k		可选的		flag选项，detach 后杀掉 session。
-v		可选的		flag选项，开启后显示更多日志。
-h		查看帮助。
```

## update 子命令

执行`git pull`更新`pwncli`，省去手动进入仓库目录拉取的步骤。

输入`pwncli update -h`得到帮助信息：

```
Usage: pwncli update [OPTIONS]

Options:
  -d, --dir TEXT  The directory of pwncli repository, it's used to execuate
                  `git pull' command.
  -v, --verbose   Show more info or not.
  -h, --help      Show this message and exit.
```

**选项**：

```
-d		可选的		pwncli仓库目录，命令会在该目录下执行git pull。未指定时尝试自动定位。
-v		可选的		flag选项，开启后显示更多日志。
-h		查看帮助。
```

# 依赖库

`pwncli`的依赖库清单如下所示：

```
click
pwntools
PySocks
requests
ropper
```

其中`click`负责命令行框架，`pwntools`是底层的pwn攻击库，`PySocks`与`requests`用于代理连接和在线libc搜索，`ropper`提供gadget搜索后端。完整依赖以`pyproject.toml`中的`dependencies`为准。

# 截图示例

### pwncli 示例

![image-20220226232019621](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232019621.png)

### debug 示例

`pwncli -vv debug ./test`：

![image-20220226232116090](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232116090.png)

`pwncli -vv debug ./test -t`：

![image-20220226232356871](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232356871.png)



`pwncli de ./test -t -b main`：

![image-20220226232710687](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232710687.png)

这个时候没有断住：

`pwncli de ./test -p -t -b main`：

![image-20220226232858593](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232858593.png)

![image-20220226232946892](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226232946892.png)



`pwncli de ./test -H puts`：

![image-20220226233434698](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233434698.png)

`pwncli de ./test -t -s "vmmap;b main"`：

![image-20220226233628316](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233628316.png)



`pwncli de ./test -w`：

![image-20220226233900484](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226233900484.png)



`pwncli de ./test -w -m wsl-u`：

![image-20220226234010903](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234010903.png)



`pwncli de ./test -w -m wsl-wts`：

![image-20220226234057770](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234057770.png)



`pwncli de ./test -t -g pwndbg`：

![image-20220226234152877](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234152877.png)



`pwncli de ./test -u`:

![image-20220226234307876](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226234307876.png)

### remote 示例

`pwncli re ./test 127.0.0.1:10001`：

![image-20220226235042604](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235042604.png)



`pwncli -vv re ./test -i 127.0.0.1 -p 10001`：

![image-20220226235158851](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235158851.png)



`pwncli -vv re 127.0.0.1:10001`：

![image-20220226235248653](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235248653.png)

### config 示例

`pwncli config list example`：

![image-20220226235423624](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235423624.png)

### setgdb 示例

`pwncli gadget ./test`：

![image-20220226235602674](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235602674.png)



`sudo pwncli setgdb -g`：

![image-20220226235738869](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235738869.png)

### patchelf 示例

`pwncli patchelf ./test -b 2.31`：

![image-20220226235851991](https://github.com/RoderickChan/pwncli/blob/main/img/image-20220226235851991.png)

### qemu 示例

**TODO**

