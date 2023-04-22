import os
import ctypes
import errno
import contextlib
import pathlib
import re


SCMP_ACT_ALLOW = 0x7fff0000
SCMP_ACT_ERRNO = 0x00050000

libseccomp = ctypes.CDLL("libseccomp.so.2")


@contextlib.contextmanager
def seccomp_load(default_action):
    ctx = libseccomp.seccomp_init(default_action)
    try:
        yield ctx
        print(libseccomp.seccomp_load(ctx))
    finally:
        libseccomp.seccomp_release(ctx)


def seccomp_allow(syscalls):
    with seccomp_load(SCMP_ACT_ERRNO | errno.EPERM) as ctx:
        added = set()
        for syscall in syscalls:
            if isinstance(syscall, str):
                syscall = libseccomp.seccomp_syscall_resolve_name(syscall)
            if syscall in added:
                continue
            libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 0)


def seccomp_block(syscalls):
    print("blocking", syscalls)
    with seccomp_load(SCMP_ACT_ALLOW) as ctx:
        added = set()
        for syscall in syscalls:
            if isinstance(syscall, str):
                syscall = libseccomp.seccomp_syscall_resolve_name(syscall)
            if syscall in added:
                continue
            libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ERRNO | errno.EPERM, syscall, 0)
