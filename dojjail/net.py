import subprocess

from .utils import sbin_which


def ip_run(command, *, check=True):
    try:
        return subprocess.run([sbin_which("ip"), *command.split()],
                              stdin=subprocess.DEVNULL,
                              encoding="ascii",
                              capture_output=True,
                              check=check)
    except subprocess.CalledProcessError as e:
        raise Exception(e.stderr)


def iptables_load(rules):
    try:
        return subprocess.run([sbin_which("iptables-restore")],
                              input=rules,
                              encoding="ascii",
                              capture_output=True,
                              check=True)
    except subprocess.CalledProcessError as e:
        raise Exception(e.stderr)
