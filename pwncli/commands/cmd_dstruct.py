#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : cmd_dstruct.py
@Desc    : Display struct info of a binary by gdb.
'''

import os
import sys
import tempfile

import click
from pwn import which

from ..cli import _set_filename, pass_environ


@click.command(name="dstruct", short_help="Display struct info by gdb.")
@click.argument('filename', type=str, default=None, required=False, nargs=1)
@click.option('-s', '--save-all', "save_all", is_flag=True, show_default=True, help="Save all struct info or not.")
@click.option('-d', '--dir', '--directory', "directory", type=click.Path(exists=True, dir_okay=True), default=".", required=False, help="The directory to save files.")
@click.option('-n', '--name',  "name", default=[], type=str, multiple=True, show_default=True, help="The name of struct you want to show.")
@pass_environ
def cli(ctx, filename, save_all, directory, name):
    """
    FILENAME: 二进制文件名。

    \b
    pwncli dstruct ./vmlinux -n cred -n tty_struct

    pwncli ds ./vmlinux -s
    """
    ctx.verbose = 2
    _set_filename(ctx, filename)
    if not ctx.get('filename'):
        ctx.abort(
            "dstruct-command ---> No filename, please specify the binary file.")

    if not which("gdb"):
        ctx.abort("dstruct-command ---> No gdb, please install gdb first.")

    write_path = ""
    if save_all:
        write_path = os.path.join(
            directory, os.path.basename(filename)+"_struct_info.txt")

    # 步骤1：通过 gdb 获取结构体信息
    struct_name = []
    with tempfile.NamedTemporaryFile(mode="a+t") as tf:
        # print(tf.name)
        cmd = "gdb -q {} -batch -ex 'set logging file {}' -ex 'set logging on' -ex 'info types' -ex 'set logging off' >/dev/null".format(
            filename, tf.name)
        ctx.vlog("dstruct-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)

        for line in tf:
            line = line.strip().rstrip(";")
            if line.startswith("struct "):
                struct_name.append(line)

    name = ["struct " + n.strip() if not n.strip().startswith("struct")
            else n.strip() for n in name]
    for n in name:
        if n not in struct_name:
            ctx.abort(
                "dstruct-command ---> Invalid name: {}, cannot find this struct.".format(n))

    # 默认打印全部
    if len(name) == 0:
        res = input(
            "[*] No struct name is given, display all struct info in {}, continue? [y/n]".format(filename)).strip().lower()
        if res != "y":
            sys.exit(0)
        name = struct_name

    # 步骤2：显示信息
    with tempfile.NamedTemporaryFile(mode="w+t", suffix=".py") as tf:
        cmd = "gdb -q {} -batch".format(filename)
        if write_path:
            cmd += " -ex 'set logging file {}' -ex 'set logging on'".format(
                write_path)
        cmd += " -ex 'source {}'".format(tf.name)
        if write_path:
            cmd += " -ex 'set logging off'"

        content = """
import gdb

class MyGetOffset(gdb.Command):
    def __init__(self):
        super(self.__class__, self).__init__("get-offset", gdb.COMMAND_DATA)

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) != 1:
            raise GdbError('get-offset need only 1 argument.')
        struct_type = gdb.lookup_type(argv[0])
        print("[{{}}] size: {{}}  {{}}".format(argv[0], struct_type.sizeof, hex(struct_type.sizeof)))
        print(" {{")
        for field in struct_type.fields():
            print("  {{}} ---> {{}}".format(hex(field.bitpos // 8), field.name))
        print(" }}")
        print("\\n"+"-"*60+"\\n")

MyGetOffset()

for s in {}:
    try:
        gdb.execute("pt /o {{}}".format(s))
        print("\\n"+"-"*60+"\\n")
    except:
        try:
            gdb.execute('get-offset "{{}}"'.format(s))
        except:
            pass
        pass
""".format(repr(name))
        tf.write(content)
        tf.flush()

        # os.system(f"cat {tf.name}")
        ctx.vlog("dstruct-command ---> Exec cmd: {}".format(cmd))
        os.system(cmd)
