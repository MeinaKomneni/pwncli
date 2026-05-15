#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : consts.py
@Desc    : Common C/Linux macro constants for CTF use.
           Quick reference when you can't Google during offline exams.
'''

__all__ = ["Consts"]


class Consts:
    """Common C/Linux constants. Use `Consts.show()` to print all, or
    access individual values like `Consts.mmap.PROT_EXEC`."""

    class mmap:
        """mmap(addr, length, prot, flags, fd, offset)"""
        # prot
        PROT_NONE = 0x0
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        PROT_RWX = 0x7

        # flags
        MAP_SHARED = 0x01
        MAP_PRIVATE = 0x02
        MAP_FIXED = 0x10
        MAP_ANONYMOUS = 0x20
        MAP_ANON = 0x20
        MAP_GROWSDOWN = 0x0100
        MAP_POPULATE = 0x8000
        MAP_STACK = 0x20000

    class open:
        """open(pathname, flags, mode)"""
        O_RDONLY = 0
        O_WRONLY = 1
        O_RDWR = 2
        O_CREAT = 0o100       # 0x40
        O_EXCL = 0o200        # 0x80
        O_TRUNC = 0o1000      # 0x200
        O_APPEND = 0o2000     # 0x400
        O_NONBLOCK = 0o4000   # 0x800
        O_DIRECTORY = 0o200000  # 0x10000

        AT_FDCWD = -100  # 0xffffff9c as signed

    class mprotect:
        """mprotect(addr, len, prot) — prot values same as mmap"""
        PROT_NONE = 0x0
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        PROT_RWX = 0x7

    class signal:
        """signal numbers"""
        SIGHUP = 1
        SIGINT = 2
        SIGQUIT = 3
        SIGILL = 4
        SIGTRAP = 5
        SIGABRT = 6
        SIGBUS = 7
        SIGFPE = 8
        SIGKILL = 9
        SIGUSR1 = 10
        SIGSEGV = 11
        SIGUSR2 = 12
        SIGPIPE = 13
        SIGALRM = 14
        SIGTERM = 15
        SIGCHLD = 17
        SIGCONT = 18
        SIGSTOP = 19

    class socket:
        """socket(domain, type, protocol)"""
        # domain
        AF_UNIX = 1
        AF_INET = 2
        AF_INET6 = 10

        # type
        SOCK_STREAM = 1
        SOCK_DGRAM = 2
        SOCK_RAW = 3

    class clone:
        """clone flags"""
        CLONE_VM = 0x00000100
        CLONE_FS = 0x00000200
        CLONE_FILES = 0x00000400
        CLONE_SIGHAND = 0x00000800
        CLONE_THREAD = 0x00010000
        CLONE_NEWNS = 0x00020000
        CLONE_NEWPID = 0x20000000

    class fcntl:
        """fcntl commands"""
        F_DUPFD = 0
        F_GETFD = 1
        F_SETFD = 2
        F_GETFL = 3
        F_SETFL = 4

        FD_CLOEXEC = 1

    class ioctl:
        """common ioctl requests (terminal)"""
        TIOCGWINSZ = 0x5413
        TIOCSWINSZ = 0x5414

    class prctl:
        """prctl options (seccomp related)"""
        PR_SET_SECCOMP = 22
        PR_SET_NO_NEW_PRIVS = 38

        SECCOMP_MODE_STRICT = 1
        SECCOMP_MODE_FILTER = 2

    class ptrace:
        """ptrace requests"""
        PTRACE_TRACEME = 0
        PTRACE_PEEKTEXT = 1
        PTRACE_PEEKDATA = 2
        PTRACE_POKETEXT = 4
        PTRACE_POKEDATA = 5
        PTRACE_CONT = 7
        PTRACE_SINGLESTEP = 9
        PTRACE_GETREGS = 12
        PTRACE_SETREGS = 13
        PTRACE_ATTACH = 16
        PTRACE_DETACH = 17

    @classmethod
    def show(cls, group=None):
        """Print all constants or a specific group.

        Args:
            group: Optional group name (e.g. "mmap", "open"). None = all.
        """
        groups = {k: v for k, v in cls.__dict__.items()
                  if isinstance(v, type) and not k.startswith('_')}

        if group:
            if group not in groups:
                print(f"Unknown group '{group}'. Available: {', '.join(groups)}")
                return
            groups = {group: groups[group]}

        for name, grp in groups.items():
            doc = grp.__doc__ or ""
            print(f"\n{'='*50}")
            print(f" {name}  —  {doc.strip()}")
            print(f"{'='*50}")
            for k, v in grp.__dict__.items():
                if k.startswith('_'):
                    continue
                if isinstance(v, int):
                    if v < 0:
                        print(f"  {k:<20s} = {v} ({hex(v & 0xffffffff)})")
                    else:
                        print(f"  {k:<20s} = {v:#x} ({v})")
