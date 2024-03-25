import os
import pathlib

from .prctl import set_parent_death_signal


def fork_clean():
    pid = os.fork()
    if not pid:
        set_parent_death_signal()
    return pid


def sbin_which(program):
    for dir in ["/sbin", "/usr/sbin"]:
        path = pathlib.Path(dir, program)
        if path.exists():
            return str(path)
    else:
        raise Exception(f"`{program}` not found")
