"""共享状态总线 gift，以及 pwncli 脚本模式的初始化入口。"""

from collections import OrderedDict

from pwn import context, which

from .env import _in_tmux

__all__ = [
    "gift",
    "init_pwn_context",
]


class _Inner_Dict(OrderedDict):
    def __getattr__(self, name):
        if name not in self.keys():
            return None
        return self[name]

    def __setattr__(self, name, value):
        self[name] = value

gift = _Inner_Dict() # 公共属性


def _assign_globals_init(_io, **context_kwargs):

    if "log_level" not in context_kwargs:
        context_kwargs['log_level'] = "debug"

    if "endian" not in context_kwargs:
        context_kwargs['endian'] = "little"

    if "timeout" not in context_kwargs:
        context_kwargs['timeout'] = 5

    if "os" not in context_kwargs:
        context_kwargs['os'] = "linux"

    if _in_tmux():
        context_kwargs['terminal'] = ["tmux", "splitw", "-h"]
    elif which("gnome-terminal"):
        context.terminal = ["gnome-terminal", "--", "sh", "-c"]

    context.update(**context_kwargs)
    gift.io = _io


def init_pwn_context(io, arch="amd64", **context_kwargs):
    """ 用法：

    from pwncli import *

    p = process(xxx)
    p = remote(x.x.x.x, 1337)

    init_pwn_context(p)
    """
    context_kwargs['arch'] = arch
    _assign_globals_init(io, **context_kwargs)
