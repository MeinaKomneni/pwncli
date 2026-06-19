

# gadgetbox — Gadget 搜索系统

`pwncli/utils/toolkit/gadgetbox.py` 提供三种 gadget 搜索后端，`pwncli/utils/runtime/current_gadgets.py` 中的 `CurrentGadgets` 提供脚本模式的高级接口和 ROP 链构建器。

***

## 1 底层 GadgetBox

三种后端，共享 `_GadgetBase` 接口：

```python
# ROPgadget 命令行（需安装 ROPgadget）
box = RopgadgetBox(debug=False)

# pwntools ELF.search
box = ElfGadgetBox(debug=False)

# ropper Python API（需安装 ropper）
box = RopperBox(badbytes='', inst_count=10, op_type=RopperOptionType.all, debug=False)
```

### 通用接口

```python
box.add_file("elf", "./pwn", "amd64")
box.add_file("libc", "./libc.so.6")     # arch 自动检测
box.set_imagebase("libc", 0x7f000000)

# 搜索
addr = box.search_gadget("pop rdi ; ret", "elf")
addr = box.search_opcode("5fc3", "elf")
addr = box.search_string("/bin/sh", "libc")
addrs = box.search_opcode("5fc3", "elf", get_list=True)
```

### 预定义 gadget（amd64）

```python
box.get_pop_rdi_ret()           # 5fc3
box.get_pop_rsi_ret()           # 5ec3
box.get_pop_rdx_ret()           # 5ac3
box.get_pop_rdx_rbx_ret()       # 5a5bc3
box.get_pop_rdx_xor_eax_ret()   # 5a31c0c3
box.get_pop_rdx_xor_eax_pop4_ret()  # pop rdx; xor eax,eax; pop rbx; pop r12; pop r13; pop rbp; ret
box.get_pop_rax_ret()           # 58c3
box.get_pop_rbx_ret()           # 5bc3
box.get_pop_rcx_ret()           # 59c3
box.get_pop_rcx_rbx_ret()       # 595bc3
box.get_pop_rbp_ret()           # 5dc3
box.get_pop_rsp_ret()           # 5cc3
box.get_pop_rsi_r15_ret()       # 5E415FC3
box.get_ret()                   # c3
box.get_leave_ret()             # c9c3
box.get_syscall()               # 0f05
box.get_syscall_ret()           # 0f05c3
box.get_bin_sh()                # "/bin/sh" 字符串
box.get_magic_gadget()          # add dword ptr [rbp-0x3d], ebx; ret
box.get_int80()                 # cd80 (i386)
box.get_int80_ret()             # cd80c3 (i386)
```

### RopperBox 专有

```python
box = RopperBox(op_type=RopperOptionType.all)  # rop/jop/sys/all
box.update_option(badbytes='0a00')
box.print_gadgets("elf")
box.clear_cache()
```

***

## 2 CurrentGadgets — 脚本模式高级接口

`CurrentGadgets`（别名 `CG`）自动使用 `gift.elf` 和 `gift.libc`。

```python
load_currentgadgets_background(find_in_elf=True, find_in_libc=True)
CG.set_find_area(find_in_elf=True, find_in_libc=False)
```

### 单个 gadget

```python
CG.pop_rdi_ret()            CG.pop_rsi_ret()
CG.pop_rdx_ret()            CG.pop_rdx_rbx_ret()
CG.pop_rdx_xor_eax_ret()    CG.pop_rdx_xor_eax_pop4_ret()
CG.pop_rax_ret()            CG.pop_rbx_ret()
CG.pop_rcx_ret()            CG.pop_rcx_rbx_ret()
CG.pop_rbp_ret()            CG.pop_rsp_ret()
CG.pop_rsi_r15_ret()        CG.pop_pop_ret()
CG.pop_pop_pop_ret()        CG.pop_pop_pop_pop_ret()
CG.pop_pop_pop_pop_pop_ret()
CG.pop_pop_pop_pop_pop_pop_ret()
CG.ret()                    CG.leave_ret()
CG.syscall()                CG.syscall_ret()
CG.bin_sh()                 CG.sh()
CG.magic_gadget()           CG.mov_rsp_rdx_ret()
```

### 自定义搜索

```python
CG.find_gadget("pop rdi; ret", find_type='asm')
CG.find_gadget("5fc3", find_type='opcode')
CG.find_gadget("/bin/sh", find_type='string')
CG.find_gadget("5fc3", find_type='opcode', get_list=True)
```

### ROP 链构建器

```python
# execve("/bin/sh", 0, 0) — i386/amd64 自适应
payload = CG.execve_chain(bin_sh_addr=None)

# mprotect
payload = CG.mprotect_chain(va=addr, length=0x1000, prog=7)

# open-read-write
payload = CG.orw_chain(flag_addr, buf_addr=None, flag_fd=3, write_fd=1, buf_len=0x30)

# openat-read-write（绕过 seccomp 禁 open）
payload = CG.otrw_chain(flag_addr)

# 单个 syscall
payload = CG.syscall_chain(syscall_num=59, para1=bin_sh, para2=0, para3=0)
payload = CG.open_chain(fileaddr, flag=0, mode=None)
payload = CG.openat_chain(fileaddr, flag=0)
payload = CG.read_chain(fd=3, buf=buf_addr, length=0x30)
payload = CG.write_chain(fd=1, buf=buf_addr, length=0x30)
```

### 高级 payload

```python
# ret2csu
payload = CG.ret2csu(edi=1, rsi=buf, rdx=8, call_array_addr=write_got, short=True)

# magic gadget 修改内存
payload = CG.write_by_magic(write_addr=target, ori=old_val, expected=new_val, short=True)

# 任意地址写
payload = CG.write8bytes_at_addr(addr=target, number=value)
payload = CG.write_at_addr(addr=target, payload=b"data...")

# 内存拷贝 (rep movsb)
payload = CG.copy_byte2byte(src_addr=src, dst_addr=dst, length=0x100, do_cld=True)

# 栈迁移 gadget 系列
addr = CG.stack_pivot_from_rdi_gadget()
addr = CG.control_rdx_from_rdi_gadget()
payload = CG.stack_pivot_from_rdi_gadget_rdi_payload(rdi_addr, ropchain)
payload = CG.control_rdx_from_rdi_gadget_payload(rdi_addr, ropchain)
payload = CG.control_rdx_from_rdi_gadget_payload_system_binsh(rdi_addr, system_addr)
```
