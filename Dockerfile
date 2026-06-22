FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm

# pwntools / ropper 需要的系统库与工具链：
# libffi-dev、libssl-dev、python3-dev 供编译 C 扩展；binutils 给 pwntools 的反汇编；
# gdb 让 debug 子命令可用；git 用于 editable 安装时定位仓库。
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python3-dev \
        libffi-dev libssl-dev binutils gdb \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pwncli
COPY . .

# 先升级 pip 与 setuptools：22.04 自带的 setuptools 59.x 不支持 PEP 660 的
# build_editable hook，会导致 editable 安装失败。
RUN pip3 install --upgrade pip setuptools

# 对齐 README 推荐的 editable 安装方式。
# Ubuntu 22.04 未启用 PEP 668 外部环境保护，故无需 --break-system-packages。
RUN pip3 install --editable .

# 烟雾测试：版本号、库导入、子命令枚举三关，任一失败即令构建报错。
RUN pwncli --version \
    && python3 -c "import pwncli; from pwncli import gift" \
    && pwncli --help | grep -q -E 'debug|remote|gadget'

# 默认进入交互式 shell，方便进入容器后手动验证各子命令。
CMD ["bash"]
