# 拆分 decorates：通用装饰器归 core，枚举攻击机制归 toolkit

## 动机

utils 分层后，`decorates.py` 落在 `toolkit/`，但语义上它是通用装饰器、本该属于 `core/`。把它拽进 toolkit 的污染物是其中混入的 PWN 枚举攻击机制——`local_enumerate_attack`/`remote_enumerate_attack` 及其辅助函数用了 `ldd_get_libc_path`、`ELF`、`process`、`tube`，这些 PWN 依赖让一个本来通用的装饰器模块无法下沉到 core。这次把两者拆开，让通用装饰器归位 core，PWN 机制留在 toolkit。

## 方案

把原 `toolkit/decorates.py` 按职责一分为二：

| 新模块 | 内容 | 依赖 |
|--------|------|------|
| `core/decorates.py` | 通用装饰器：timer/retry/cache_result/cache_nonresult/bomber/sleep_call_*/sleeper/limit_calls/call_multimes/always_success/deprecated/unused/show_name/add_prompt/signature2name/count_calls/convert_str2bytes/convert_bytes2str | 仅 `core.log`（无 pwn、无 onegadget） |
| `toolkit/enumerate_attack.py` | 枚举攻击机制：_light_enumerate_attack/local_enumerate_attack/remote_enumerate_attack/_call_func_invoke/_attack_local/_attack_remote/_check_func_args/_EnumerateAttackMode | `core.exceptions`、`core.log`、`onegadget.ldd_get_libc_path`、pwn(ELF/process/remote/tube) |

依赖方向仍严格 `runtime → toolkit → core`，无环。`_check_func_args` 随枚举攻击机制留在 toolkit，被 runtime 的 `cli_decorates`（`smart_enumerate_attack`）复用，方向 runtime→toolkit 合法。

## API

公共 API 不变，`from pwncli import *` 仍为 513 个符号。通用装饰器改由 `core` 导出（经 `utils/__init__` 聚合，对外无感）。

`local_enumerate_attack`/`remote_enumerate_attack` 维持原状不计入 `__all__`（`enumerate_attack.__all__ = []`），需显式导入：`from pwncli.utils.toolkit.enumerate_attack import local_enumerate_attack`。这保留了拆分前的可见性——它们此前也不在 `decorates.__all__` 里。

直接路径变化：`pwncli.utils.toolkit.decorates` 拆为 `pwncli.utils.core.decorates`（通用装饰器）与 `pwncli.utils.toolkit.enumerate_attack`（枚举攻击）。

## 改动文件

- 新增：`utils/core/decorates.py`、`utils/toolkit/enumerate_attack.py`
- 删除：`utils/toolkit/decorates.py`
- `utils/core/__init__.py`：新增 decorates 的 re-export（置于 log 之后，满足 decorates→log 依赖序）
- `utils/toolkit/__init__.py`：decorates 替换为 enumerate_attack
- 消费者 import 改写：`commands/cmd_template.py`（limit_calls→core）、`runtime/gdb_helper.py`（always_success 等→core）、`toolkit/pipes.py`（bomber→core）、`runtime/cli_decorates.py`（_check_func_args→toolkit.enumerate_attack）、`tests/util_test/test_recent_features.py`（装饰器→core）

## 实现要点

用脚本按行区间切分而非手抄 600 行：通用装饰器区间（含 `_SleepMode` 与 `sleep_call_*`）写入 core/decorates，枚举攻击区间（含 `_EnumerateAttackMode` 与末尾文档字符串）写入 enumerate_attack，各自配只含所需依赖的 header。切分后核对 core/decorates 不含任何 pwn/onegadget 引用，确保它真正属于 core。

## 验证

`from pwncli import *` 符号数 513 不变；`core.decorates` 与 `toolkit.enumerate_attack` 路径可用且对象身份一致；13 个 CLI 命令全部可导入；util_test 排除网络依赖的 test_libcbox 后 45 passed / 1 skipped。
