import os

from dojjail import Host


def test_simple():
    host = Host("host", seccomp_block=["getppid"])
    host.run()

    def except_getppid():
        return False

    assert host.exec(except_getppid) == PermissionError
