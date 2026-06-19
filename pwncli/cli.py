"""pwncli 主命令模块，入口点为 'cli'

pwncli 是一个基于 click 与 pwntools 的 CTF PWN 攻击命令行工具，
同时也可通过其他 Python 脚本调用。pwncli 的目标是 "Just pwn, don't waste time on preparing exp"。

click 示例见 https://github.com/pallets/click/tree/main/examples/complex
感谢 click，它是一个出色的 Python CLI 工具。
"""
import os
import pathlib
import sys

import click

from .utils.core.config import read_ini, try_get_config_data_by_key
from .utils.core.state import gift
from .utils.core.log import errlog_ex, log2_ex, log_ex

__all__ = ['cli_script', 'set_gdb_script']


_CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
_PWNCLI_DIR_NAME = os.path.dirname(os.path.abspath(__file__))

class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        cmd = click.Group.get_command(self, ctx, cmd_name)
        if cmd is not None:
            return cmd
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        else:
            ctx.fail('\033[31mcli --> Too many matches: %s\033[0m' % ', '.join(sorted(matches)))


class CommandsAliasedGroup(click.Group):
    def __init__(self, name=None, **attrs):
        click.Group.__init__(self, name, **attrs)
        self._all_commands = []
        self._used_commands = []
        # 获取所有命令
        cmd_folder = os.path.join(_PWNCLI_DIR_NAME, "commands")
        for filename in os.listdir(cmd_folder):
            if filename.endswith(".py") and filename.startswith("cmd_"):
                self._all_commands.append(filename[4:-3])
        if len(self._all_commands) == 0:
            raise click.Abort("No command!")
        self._all_commands.sort()
        self._used_commands = self._all_commands
        

    def add_command(self, name:str=None):
        """从 `commands` 文件夹添加命令"""
        if name is None:
            self._used_commands = self._all_commands
            return
        
        if name not in self._all_commands:
            raise click.Abort("No command named %s" % name)
        
        if name not in self._used_commands:
            self._used_commands.append(name)
            self._used_commands.sort()
        
    
    def del_command(self, name:str=None):
        """删除命令"""
        if name is None or (name not in self._used_commands):
            return
        self._used_commands.remove(name)


    def list_commands(self, ctx):
        return tuple(self._used_commands)


    def get_command(self, ctx, cmd_name):
        matches = [x for x in self._used_commands if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            try:
                mod = __import__("pwncli.commands.cmd_{}".format(matches[0]), None, None, ["cli"])
            except ImportError:
                raise
            cmd = mod.cli
            if 'help_option_names' not in cmd.context_settings:
                has_dash_h = any('-h' in p.opts for p in cmd.params)
                if not has_dash_h:
                    cmd.context_settings['help_option_names'] = ['-h', '--help']
            return cmd
        else:
            ctx.fail('\033[31mpwncli --> Too many matches: %s\033[0m' % ', '.join(sorted(matches)))
        
        

class Environment:
    global gift
    def __init__(self):
        self.gift = gift
        self.config_data = None
        self._log = log_ex
        self._log2 = log2_ex
        self._errlog = errlog_ex
    
    def get(self, item):
        return self.gift.get(item, None)

    def abort(self, msg=None, *args):
        if not msg:
            msg = "EXIT!"
        if args:
            msg %= args
        click.secho("[---] Abort: {}".format(msg), fg='red', err=1)
        raise click.Abort()

    def vlog(self, msg, *args):
        """仅在 verbose 启用时向标准输出记录一条消息。"""
        if self.verbose:
            self._log(msg, *args)


    def vlog2(self, msg, *args):
        """仅在 verbose 启用时向标准输出记录一条消息。"""
        if int(self.verbose) > 1:
            self._log2(msg, *args)


    def verrlog(self, msg, *args):
        """仅在 verbose 启用时向标准错误记录一条消息。"""
        if self.verbose:
            self._errlog(msg, *args)


pass_environ = click.make_pass_decorator(Environment, ensure=True)

def _set_filename(ctx, filename, msg=None):
    if filename:
        # 设置 filename 并检查
        fileptah = pathlib.Path(filename)
        if fileptah.exists() and fileptah.is_file():
            ctx.gift.filename = filename
            if not msg:
                ctx.vlog("pwncli --> Set 'filename': {}".format(filename))
            else:
                ctx.vlog(msg)
        else:
            ctx.abort("pwncli --> Wrong filename: {}!".format(filename))


@click.command(cls=CommandsAliasedGroup, context_settings=_CONTEXT_SETTINGS)
@click.option('-f', '--filename', type=str, default=None, show_default=True, help="Elf file path to pwn.")
@click.option('-v', '--verbose', count=True, help="Show more info or not.")
@click.option('-E', '-ea', '--extra-argv', "extra_argv", type=str, default="", required=False, show_default=True, help="The extra argv for this script, sometimes it's useful for bruteforce.")
@click.version_option('1.6', "-V", "--version", prog_name='pwncli', message="%(prog)s: version %(version)s\nauthor: roderick chan\ngithub: https://github.com/RoderickChan/pwncli")
@pass_environ
def cli(ctx, filename, verbose, extra_argv): # ctx: 命令属性
    """pwncli —— 面向 pwner 的工具！

    \b
    CLI 用法：
        pwncli -v subcommand args
    Python 脚本用法：
        脚本内容：
            from pwncli import *
            cli_script()
        然后从命令行启动：
            ./yourownscript -v subcommand args
    """
    ctx.verbose = verbose
    ctx.cli_mode = sys.argv[0].endswith(('/pwncli', '\\pwncli')) # 从 CLI 还是 Python 脚本使用此工具
    ctx.pwncli_path = _PWNCLI_DIR_NAME
    if verbose:
        ctx.vlog("pwncli --> Open 'verbose' mode")

    if ctx.cli_mode:
        ctx.vlog("pwncli --> Command line mode is used.")
    else:
        ctx.gift.script_mode = True
        ctx.vlog("pwncli --> Script mode is used.")
        ctx.gift['no_stop'] = False
    _set_filename(ctx, filename)

    # 初始化配置文件
    ctx.config_data = read_ini(os.path.expanduser('~/.pwncli.conf'))
    if ctx.config_data:
        ctx.vlog("pwncli --> Read config data from ~/.pwncli.conf success!")
    else:
        ctx.vlog2("pwncli --> Cannot read config data from ~/.pwncli.conf!")

    # 读取配置数据并为 debug 与 remote 设置
    to = try_get_config_data_by_key(ctx.config_data, 'context', 'timeout')
    ctx.gift.context_timeout = to if to else 10 # 设置默认超时

    ll = try_get_config_data_by_key(ctx.config_data, 'context', 'log_level')
    ctx.gift.context_log_level = ll if ll else 'debug' # 设置默认日志级别


    # 初始化 debug/remote 标志
    ctx.gift.debug = False
    ctx.gift.remote = False

    # 本脚本的额外 argv
    ctx.gift.extra_argv = extra_argv
    

def set_gdb_script(script: str):
    """为 debug 命令设置 gdb 脚本。

    在 cli_script() 之前调用。脚本存储在 gift 中，
    由 debug 命令自动读取。
    """
    merged = ";".join(line for line in script.strip().splitlines() if line.strip())
    gift['gdb_script'] = merged


def cli_script():
    try:
        cli.main(standalone_mode=False)
    except click.exceptions.UsageError as e:
        if e.ctx:
            click.echo(e.ctx.get_help())
        else:
            click.echo(e.format_message())
        sys.exit(1)



