#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_setgdb.py
@Desc    : Copy gdbinit files and generate gdb wrapper scripts for current user.
'''

import os
import sys

import click

from ..cli import pass_environ


@click.command(name="setgdb", short_help="Copy gdbinit files from and set gdb-scripts for current user.")
@click.option('-g', '--generate-script', "generate_script", is_flag=True, show_default=True, help="Generate the scripts of gdb-gef/gdb-pwndbg/gdb-peda in /bin or $HOME/.local/bin or not.")
@click.confirmation_option(prompt="Copy gdbinit files from pwncli/conf/.gdbinit-* to user directory?", expose_value=False)
@pass_environ
def cli(ctx, generate_script):
    """
    \b
    pwncli setgdb

    """
    ctx.verbose = 2
    if sys.platform != "linux":
        ctx.abort("setgdb-command ---> This command can only be used in linux.")
    predir = os.path.join(os.environ['HOME'], ".local", "bin")
    if os.getuid() == 0:
        predir = "/bin"

    gdbinit_file_path = os.path.join(ctx.pwncli_path, "conf/.gdbinit-")

    if generate_script:
        for name in ("pwndbg", "gef", "peda"):
            _cur_path = os.path.join(predir, "gdb-{}".format(name))
            write_data = "#!/bin/sh\n"
            write_data += 'cat > ~/.gdbinit << "EOF"\n'
            with open(gdbinit_file_path+name, "rt", encoding="utf-8", errors="ignore") as gdbinitf:
                write_data += gdbinitf.read()
            if os.path.isfile(os.path.join(os.getenv('HOME'), ".d2d.py")):
                write_data += "\nsource ~/.d2d.py\n"
            write_data += '\nEOF\n'
            write_data += "\nexec gdb \"$@\"\n"
            with open(_cur_path, "wt", encoding="utf-8", errors="ignore") as file:
                file.write(write_data)
                ctx.vlog(
                    "setgdb-command ---> Generate {} success.".format(_cur_path))
            os.system("chmod 755 {}".format(_cur_path))
