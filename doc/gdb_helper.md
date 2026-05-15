

# gdb_helper — GDB 调试辅助

`pwncli/utils/gdb_helper.py` 提供在 GDB 中动态定义结构体、执行命令和设置断点的底层函数。脚本模式下建议使用 `cli_misc.py` 中的 `add_struct2current_gdb_*` 封装。

***

## 1 执行 GDB 命令

```python
execute_cmd_in_gdb(gdb_obj, "b *0x401234; c")
# 多条命令用 ; 或 \n 分隔
# tmux 环境下通过 tmux send-keys 发送
```

## 2 PIE 断点（需 pwndbg）

```python
set_pie_breakpoints(gdb_obj, offset=0x1234)
tele_pie_content(gdb_obj, offset=0x1234, number=10)
```

## 3 动态定义结构体

### 方式 1：通过成员定义

```python
add_struct_by_member(
    gdb_obj,
    "struct student",       # 结构体名
    True,                   # add_show_cmd: 注册 GDB 查看命令
    "char *teachers[10]",   # 可变参数: 完整声明
    name="i8 *",            # 关键字参数: 名称=类型
    id="u64",
    grade="size_t"
)
```

无 `struct` 前缀时自动生成 typedef：

```python
add_struct_by_member(gdb_obj, "Point", True, x="i32", y="i32")
# 生成: typedef struct { i32 x; i32 y; } Point; Point Point_var;
```

### 方式 2：通过 C 代码定义

```python
add_struct_by_file(gdb_obj, """
typedef struct {
    int id;
    char name[32];
    struct node *next;
} node_t;
""", True, "node_t")
```

自动注入的内置类型：`u8`/`u16`/`u32`/`u64`、`i8`/`i16`/`i32`/`i64`、`uint8_t`~`uint64_t`、`int8_t`~`int64_t`、`BYTE`/`byte`/`size_t`。

**原理**：将 C 代码编译为带调试信息的 .so，通过 `add-symbol-file` 加载到 GDB。

### 注册查看命令

```python
add_show_struct_command(gdb_obj, "struct student", "node_t")
# 注册 pwncli_show_student 和 pwncli_show_node_t 命令
# GDB 中使用: pwncli_show_student 0x7fffffffde00
```

## 4 终止 GDB

```python
kill_gdb(gdb_obj)   # 传 gdb 对象或 pid
```
