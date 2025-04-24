import ctypes
import enum
import os


libc = ctypes.CDLL("libc.so.6", use_errno=True)


class CAP(enum.IntFlag):
    CHOWN            = 1 << 0
    DAC_OVERRIDE     = 1 << 1
    DAC_READ_SEARCH  = 1 << 2
    FOWNER           = 1 << 3
    FSETID           = 1 << 4
    KILL             = 1 << 5
    SETGID           = 1 << 6
    SETUID           = 1 << 7
    SETPCAP          = 1 << 8
    LINUX_IMMUTABLE  = 1 << 9
    NET_BIND_SERVICE = 1 << 10
    NET_BROADCAST    = 1 << 11
    NET_ADMIN        = 1 << 12
    NET_RAW          = 1 << 13
    IPC_LOCK         = 1 << 14
    IPC_OWNER        = 1 << 15
    SYS_MODULE       = 1 << 16
    SYS_RAWIO        = 1 << 17
    SYS_CHROOT       = 1 << 18
    SYS_PTRACE       = 1 << 19
    SYS_PACCT        = 1 << 20
    SYS_ADMIN        = 1 << 21
    SYS_BOOT         = 1 << 22
    SYS_NICE         = 1 << 23
    SYS_RESOURCE     = 1 << 24
    SYS_TIME         = 1 << 25
    SYS_TTY_CONFIG   = 1 << 26
    MKNOD            = 1 << 27
    LEASE            = 1 << 28
    AUDIT_WRITE      = 1 << 29
    AUDIT_CONTROL    = 1 << 30
    SETFCAP          = 1 << 31
    MAC_OVERRIDE     = 1 << 32
    MAC_ADMIN        = 1 << 33
    SYSLOG           = 1 << 34
    WAKE_ALARM       = 1 << 35
    BLOCK_SUSPEND    = 1 << 36
    AUDIT_READ	     = 1 << 37

class SECBIT(enum.IntFlag):
    NOROOT                      = 1 << 0
    NOROOT_LOCKED               = 1 << 1
    NO_SETUID_FIXUP             = 1 << 2
    NO_SETUID_FIXUP_LOCKED      = 1 << 3
    KEEP_CAPS                   = 1 << 4
    KEEP_CAPS_LOCKED            = 1 << 5
    NO_CAP_AMBIENT_RAISE        = 1 << 6
    NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7

def get_securebits():
    PR_GET_SECUREBITS = 27
    securebits = libc.prctl(PR_GET_SECUREBITS)
    if securebits == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to get securebits: {os.strerror(errno)}")
    return SECBIT(securebits)

def set_securebits(securebits):
    PR_SET_SECUREBITS = 28
    if libc.prctl(PR_SET_SECUREBITS, securebits) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to set securebits: {os.strerror(errno)}")

def limit_capabilities(capabilities):
    PR_CAPBSET_DROP             = 24
    PR_CAP_AMBIENT              = 47
    PR_CAP_AMBIENT_RAISE        = 2
    PR_CAP_AMBIENT_LOWER        = 3
    _LINUX_CAPABILITY_VERSION_3 = 0x20080522
    _LINUX_CAPABILITY_U32S_3    = 2

    class __user_cap_header_struct(ctypes.Structure):
        _fields_ = [
            ("version", ctypes.c_uint32),
            ("pid", ctypes.c_int),
        ]

    class __user_cap_data_struct(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    securebits = get_securebits() & ~SECBIT.KEEP_CAPS | (
        SECBIT.KEEP_CAPS_LOCKED |
        SECBIT.NO_SETUID_FIXUP |
        SECBIT.NO_SETUID_FIXUP_LOCKED |
        SECBIT.NOROOT |
        SECBIT.NOROOT_LOCKED
    )
    set_securebits(securebits)

    header = __user_cap_header_struct(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
    payload = (__user_cap_data_struct * _LINUX_CAPABILITY_U32S_3)()
    assert libc.capget(ctypes.pointer(header), payload) == 0

    payload[0].effective &= capabilities
    payload[1].effective &= capabilities
    payload[0].permitted &= capabilities
    payload[1].permitted &= capabilities
    payload[0].inheritable = payload[0].permitted
    payload[1].inheritable = payload[1].permitted

    effective = (payload[1].effective << 32) | payload[0].effective
    cap_last_cap = int(open("/proc/sys/kernel/cap_last_cap").read())

    for cap in range(cap_last_cap + 1):
        if not effective & (1 << cap):
            assert libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0

    assert libc.capset(ctypes.pointer(header), payload) == 0

    for cap in range(cap_last_cap):
        if effective & (1 << cap):
            assert libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) == 0
        else:
            assert libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0) == 0
