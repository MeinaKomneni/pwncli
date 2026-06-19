#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : config.py
@Time    : 2021/11/23 23:48:28
@Author  : Roderick Chan
@Email   : roderickchan@foxmail.com
@Desc    : None
'''



import configparser
import os

__all__ = [
    "read_ini",
    "try_get_config_data_by_key",
    "show_config_data_by_section",
    "show_config_data_all",
    "show_config_data_file",
    "set_config_data_by_section",
    "set_config_data_by_key",
    "write_config_data",
]

_check_data_section_ok = lambda data, section: bool(data and data.has_section(section))


def read_ini(filename:str) -> configparser.ConfigParser:
    """使用 configparser 读取 ini 文件，仅做少量检查

    Args:
        filename (str): 目标文件路径

    Returns:
        configparser.ConfigParser: 失败时返回 None
    """
    if not os.path.exists(filename):
        return None
    parser = configparser.ConfigParser()
    data = parser.read(filename)
    if len(data) == 0:
        return None
    return parser


def try_get_config_data_by_key(data:configparser.ConfigParser, section:str, key:str) -> str:
    """根据 section 名和 option 名尝试获取值，仅做少量检查

    Args:
        data (configparser.ConfigParser): 数据
        section (str): section 名
        key (str): option 名

    Returns:
        str: 值，出错时返回 None
    """
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    return val[key] if key in val else None


def show_config_data_by_section(data:configparser.ConfigParser, section:str):
    """根据 section 名打印该 section 的数据

    Args:
        data (configparser.ConfigParser): 数据
        section (str): section 名

    """
    if not _check_data_section_ok(data, section):
        return None
    val = data[section]
    print("[{}]".format(section))
    for k, v in val.items():
        print("{} = {}".format(k, v))
    print()


def show_config_data_all(data:configparser.ConfigParser):
    """显示全部配置数据

    Args:
        data (configparser.ConfigParser): 数据

    """
    if not data:
        return
    for sec in data.sections():
        show_config_data_by_section(data, sec)


def show_config_data_file(filename:str):
    """显示全部配置数据

    Args:
        filename (str): 配置数据文件路径

    """
    show_config_data_all(read_ini(filename))


def set_config_data_by_section(data:configparser.ConfigParser, section:str, **content):
    """设置配置数据中某个 section 的内容，仅做少量检查

    Args:
        data (configparser.ConfigParser): 数据
        section (str): section 名
        content (dict): 待设置的内容

    """
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None

    # 保证 key 与 value 的类型为 str
    for k, v in content.items():
        data[section][str(k)] = str(v)
    

def set_config_data_by_key(data:configparser.ConfigParser, section:str, key:str, value:str):
    """设置配置数据中某个 section 的 option 值，仅做少量检查

    Args:
        data (configparser.ConfigParser): 数据
        section (str): section 名
        key (str): option 名
        value (str): 待设置的值

    """
    section = str(section)
    if not _check_data_section_ok(data, section):
        return None

    # 保证 key 与 value 的类型为 str
    data[section][str(key)] = str(value)


def write_config_data(data:configparser.ConfigParser, filepath:str="~/.pwncli.conf") -> bool:
    """将数据写入文件

    Args:
        data (configparser.ConfigParser): 数据
        filepath (str, optional): 目标文件路径，默认为 "~/.pwncli.conf"。

    Returns:
        bool: 写入是否成功
    """
    if not data:
        return False

    if filepath.startswith("~"):
        filepath = os.path.expanduser(filepath)
    
    filepath = os.path.abspath(filepath)

    if not os.path.isfile(filepath):
        return False
    
    with open(filepath, "w") as configfile:
        data.write(configfile)
    return True