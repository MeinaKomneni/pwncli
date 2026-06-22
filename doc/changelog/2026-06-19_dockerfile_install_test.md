# 新增 Dockerfile：容器化验证 pwncli 安装链路

## 动机

pwncli 的安装依赖 `pwntools` 与 `ropper`，二者在干净环境里对系统库有隐性要求（`libffi-dev`、`libssl-dev`、`python3-dev`、`binutils` 等），纯 `pip install` 在 base 镜像里常因 C 扩展编译失败而中断。此前仓库没有任何自动化手段来验证"能否正常安装"，安装链路是否完好只能靠人工开虚拟机试，既慢又不可复现。引入一个 Dockerfile，把主安装路径固化进镜像构建，CI 里一条 `docker build` 即可冒烟测试。

## 方案

以 `ubuntu:22.04` 为基底（与 README 推荐的发行版对齐），分层装系统依赖与 Python 包，最后在 `RUN` 里跑三关烟雾测试，任一失败即令构建报错。

| 层 | 职责 |
|----|------|
| apt-get | python3/pip/venv/dev 头文件、libffi/libssl、binutils、gdb、git |
| pip 升级 | 先升 pip 与 setuptools，绕开 22.04 自带 setuptools 59.x 不支持 PEP 660 的问题 |
| editable 安装 | `pip3 install --editable .`，对齐 README 强烈推荐的本地安装方式 |
| 烟雾测试 | `pwncli --version` + `import pwncli; from pwncli import gift` + `pwncli --help` 子命令枚举 |

## API

无新增 Python API。新增构建产物与文件：

```shell
docker build -t pwncli-install-test .
docker run --rm pwncli-install-test pwncli --version
```

构建成功即等价于安装链路通畅；进入容器后可直接 `pwncli <子命令>` 手动验证。

## 改动文件

- 新增：`Dockerfile`
- 新增：`.dockerignore`（排除 `.git`、`__pycache__`、`tests`、`img`、`egg-info` 等无关物，构建上下文从 11.6MB 降至约 1.1MB）

## 实现要点

调试过程中踩了两个坑，均已固化进 Dockerfile 注释。其一，初版用了 `--break-system-packages`，但 22.04 自带 pip 较旧不认此标志，且 22.04 尚未启用 PEP 668 外部环境保护，故直接去掉。其二，editable 安装报 `build backend is missing the 'build_editable' hook`，根因是 22.04 的 setuptools 59.x 不支持 PEP 660，需先 `pip3 install --upgrade pip setuptools` 升到新版（pip 26.x、setuptools 82.x）方可。

烟雾测试用三关而非单关，是有意为之：`--version` 只证明入口脚本就位，`import pwncli; from pwncli import gift` 证明包体与 pwntools 依赖完整加载，`pwncli --help | grep` 证明 click 命令树正常注册。三者覆盖入口、导入、命令注册三个层面，单 `--version` 漏掉的导入期故障能被后两关拦住。

`ENV TERM=xterm` 是为了消掉构建期 `_curses.error: setupterm` 的无害警告，让烟雾测试输出干净。未装 tmux/pwndbg 之类调试周边——那些属运行期需求，与安装验证无关，装进去只会拖慢构建、放大失败面。

## 验证

`docker build -t pwncli-install-test .` 成功，三关烟雾测试全部通过，输出 `pwncli: version 1.6`。
