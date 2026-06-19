# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

read doc/* to learn this project more!

## What is pwncli

pwncli is a CTF PWN exploitation toolkit built on click and pwntools. It has three usage modes:
- **CLI mode**: `pwncli debug ./binary`, `pwncli remote ip port`
- **Script mode**: Python scripts call `cli_script()` to get CLI argument parsing, then access `gift['io']`, `gift['elf']`, `gift['libc']` for the pwntools objects
- **Library mode**: `from pwncli import *` for direct API access

## Build and Install

```bash
pip install --editable .
```

Entry point defined in pyproject.toml: `pwncli = "pwncli.cli:cli"`

## Running Tests

```bash
cd tests && python3 -m pytest . -vv -s --disable-warnings
```

## Architecture

### CLI Framework (pwncli/cli.py)

`CommandsAliasedGroup` auto-discovers commands from `pwncli/commands/cmd_*.py`. Commands support prefix matching (like GDB: `pwncli de` matches `debug`). Each command module exports a `cli` click command.

The `gift` dictionary (defined in `utils/core/state.py`) is the shared state bus — CLI commands populate it with `io`, `elf`, `libc`, and script-mode users read from it.

`pwncli/utils/` is layered into three subpackages by role: `core/` (generic foundation, no PWN semantics), `toolkit/` (PWN exploitation primitives, not bound to the current session), `runtime/` (operations on the current `gift` session). Dependency direction is strictly `runtime → toolkit → core`, acyclic.

### Gadget System (utils/toolkit/gadgetbox.py + utils/runtime/current_gadgets.py)

Three gadget box backends with the same `_GadgetBase` interface:
- `RopgadgetBox` — shells out to ROPgadget
- `RopperBox` — uses ropper's Python API
- `ElfGadgetBox` — uses pwntools ELF.search

`CurrentGadgets` (in `runtime/current_gadgets.py`) is the high-level static API that scripts use. It wraps a gadget box and provides named gadget accessors (`pop_rdi_ret()`, `pop_rdx_ret()`, etc.) plus chain builders (`orw_chain`, `execve_chain`, `mprotect_chain`).

Gadget search uses opcode matching. When a simple gadget isn't found, `__try_get_rdx_gadget` falls through alternatives (e.g. `pop rdx; ret` → `pop rdx; pop rbx; ret` → `pop rdx; xor eax, eax; ret` → longer variants). When adding new fallback gadgets, verify that side effects (like `xor eax, eax`) don't clobber registers set earlier in the chain — check all call sites, not just `__inner_chain`.

### Adding a New Command

Drop a `cmd_<name>.py` in `pwncli/commands/` that exports a `cli` click command. It will be auto-discovered.

## Dependencies

click, pwntools, PySocks, requests, ropper

## Changelog Convention

Every non-trivial feature or behavioral change must have a changelog entry in `doc/changelog/`. Filename format: `YYYY-MM-DD_short_slug.md`. Each entry should contain:

- **动机**: Why this change was made
- **方案**: High-level approach chosen
- **API**: Usage examples (if applicable)
- **改动文件**: Which files were touched
- **实现要点**: Key implementation details, gotchas, trade-offs

This helps future contributors (and AI agents) understand the rationale behind changes without digging through git history.
