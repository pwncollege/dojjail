import os

from dojjail import Host, Network


def test_networking():
    network = Network("router")

    host_1 = Host("host-1")
    host_2 = Host("host-2")
    host_3 = Host("host-3")

    network.connect(host_1, host_2)
    network.connect(host_2, host_3)

    network.run()

    def ping(ip):
        return f"ping -c 1 -t 1 {ip}"

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
    host = Host("host", seccomp_block=["getppid"])
    host.run()

    assert host.exec(lambda: os.getppid()) == -1
