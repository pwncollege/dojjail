import ctypes
import signal


PR_SET_PDEATHSIG  = 1

libc = ctypes.CDLL("libc.so.6")


def set_parent_death_signal(signal=signal.SIGKILL):
    libc.prctl(PR_SET_PDEATHSIG, signal)
