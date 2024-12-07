import ctypes
import enum
import functools
import multiprocessing
import operator
import os

from .utils import fork_clean


libc = ctypes.CDLL("libc.so.6")


PR_SET_DUMPABLE   = 4

class NS(enum.IntFlag):
    USER   = 0x10000000
    MOUNT  = 0x00020000
    CGROUP = 0x02000000
    UTS    = 0x04000000
    IPC    = 0x08000000
    PID    = 0x20000000
    NET    = 0x40000000
NS.ALL = functools.reduce(operator.or_, NS.__members__.values())


def new_ns(ns_flags=NS.ALL, uid_map=None):
    # TODO: use `clone` instead of `unshare` to avoid `fork` for `pid 1`

    if uid_map is None:
        uid_map = f"0 {os.getuid()} 1\n"

    unshared_event = multiprocessing.Event()
    uid_mapped_event = multiprocessing.Event()

    libc.prctl(PR_SET_DUMPABLE, True)

    pid = fork_clean()

    if pid:
        unshared_event.wait()
        set_uid_map(pid, uid_map)
        uid_mapped_event.set()

    else:
        libc.unshare(ns_flags)
        unshared_event.set()
        uid_mapped_event.wait()

    return pid


def set_uid_map(pid, uid_map):
    with open(f"/proc/{pid}/uid_map", "w") as f:
        f.write(uid_map)
    with open(f"/proc/{pid}/gid_map", "w") as f:
        f.write(uid_map)


def set_ns(pid, ns_flags=NS.ALL):
    ns_flags |= NS.USER
    ns_names = {
        NS.USER: "user",
        NS.MOUNT: "mnt",
        NS.CGROUP: "cgroup",
        NS.UTS: "uts",
        NS.IPC: "ipc",
        NS.PID: "pid_for_children",
        NS.NET: "net",
    }
    ns_paths = [f"/proc/{pid}/ns/{ns_names[ns]}" for ns in NS if ns & ns_flags]
    for ns_path in ns_paths:
        assert libc.setns(os.open(ns_path, 0), 0) == 0, ns_path
