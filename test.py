import os

from dojjail import Host, Network


def test_exec():
    host = Host()
    host.run()

    assert host.exec(lambda: 1 + 1) == 2


def test_exception():
    host = Host()
    host.run()

    def raise_exception():
        raise Exception("Test exception")

    try:
        host.exec(raise_exception)
    except Exception as e:
        assert str(e) == "Test exception"
    else:
        assert False, "Exception not raised"


def test_networking():
    network = Network()

    host_1 = Host()
    host_2 = Host()
    host_3 = Host()

    network.connect(host_1, host_2)
    network.connect(host_2, host_3)

    network.run()

    def ping(ip):
        return f"timeout 1 ping -c 1 {ip}"

    assert host_1.exec_shell(ping("10.0.0.1")).returncode == 0
    assert host_1.exec_shell(ping("10.0.0.2")).returncode == 0
    assert host_1.exec_shell(ping("10.0.0.3")).returncode != 0

    assert host_2.exec_shell(ping("10.0.0.1")).returncode == 0
    assert host_2.exec_shell(ping("10.0.0.2")).returncode == 0
    assert host_2.exec_shell(ping("10.0.0.3")).returncode == 0

    assert host_3.exec_shell(ping("10.0.0.1")).returncode != 0
    assert host_3.exec_shell(ping("10.0.0.2")).returncode == 0
    assert host_3.exec_shell(ping("10.0.0.3")).returncode == 0


def test_seccomp():
    host = Host(seccomp_block=["getppid"])
    host.run()

    assert host.exec(lambda: os.getppid()) == -1
