import contextlib
import ctypes
import errno


SCMP_ACT_ALLOW = 0x7fff0000
SCMP_ACT_ERRNO = 0x00050000

libseccomp = ctypes.CDLL("libseccomp.so.2")


def syscall_resolve(syscall):
    if isinstance(syscall, int):
        return syscall
    elif isinstance(syscall, str):
        result = libseccomp.seccomp_syscall_resolve_name(ctypes.c_char_p(syscall.encode()))
        if result == -1:
            raise ValueError(f"Unknown syscall: {syscall!r}")
        return result
    else:
        raise TypeError(f"Unknown syscall type: {type(syscall)}")


@contextlib.contextmanager
def seccomp_load(default_action):
    ctx = libseccomp.seccomp_init(default_action)
    try:
        yield ctx
        if libseccomp.seccomp_load(ctx) != 0:
            raise OSError("Failed to load seccomp filter")
    finally:
        libseccomp.seccomp_release(ctx)


def seccomp_allow(syscalls):
    with seccomp_load(SCMP_ACT_ERRNO | errno.EPERM) as ctx:
        for syscall in syscalls:
            libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_resolve(syscall), 0)


def seccomp_block(syscalls):
    with seccomp_load(SCMP_ACT_ALLOW) as ctx:
        for syscall in syscalls:
            libseccomp.seccomp_rule_add(ctx, SCMP_ACT_ERRNO | errno.EPERM, syscall_resolve(syscall), 0)
