import os
import pathlib

from .prctl import set_parent_death_signal


def fork_clean(parent_death_signal=9):
    pid = os.fork()
    if not pid and parent_death_signal is not None:
        set_parent_death_signal(parent_death_signal)
    return pid


def sbin_which(program):
    for dir in ["/sbin", "/usr/sbin"]:
        path = pathlib.Path(dir, program)
        if path.exists():
            return str(path)
    else:
        raise Exception(f"`{program}` not found")
