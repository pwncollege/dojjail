import tempfile
import dojjail
import os


def test_exec():
    host = dojjail.Host()
    host.run()

    assert host.exec(lambda: 1 + 1) == 2


def test_entrypoint():
    class TestHost(dojjail.Host):
        def entrypoint(self):
            return 42

    host = TestHost()
    host.run()

    assert host.wait() == 42

    try:
        host.wait()
    except ChildProcessError:
        pass
    else:
        assert False, "Host not terminated"


def test_exception():
    host = dojjail.Host()
    host.run()

    def raise_exception():
        raise Exception("Test exception")

    try:
        host.exec(raise_exception)
    except Exception as e:
        assert str(e) == "Test exception"
    else:
        assert False, "Exception not raised"

def test_busybox():
    host = dojjail.BusyBoxFSHost()
    host.run()
    assert b"bin" in host.exec_shell("ls /").stdout
    assert host.exec_shell("ls /tmp").stdout == b""
    assert not host.exec(lambda: os.path.exists("/flag"))

    host = dojjail.BusyBoxFSHost(flag_source="/flag")
    host.run()
    assert host.exec(lambda: os.path.exists("/flag"))
    assert host.exec_shell("cat /flag") != b""

def test_simplefs():
    td = tempfile.mkdtemp()
    host = dojjail.SimpleFSHost(src_path=td)
    host.run()
    print(host.exec(lambda: os.listdir("/")))

def test_networking():
    network = dojjail.Network()

    host_1 = dojjail.Host()
    host_2 = dojjail.Host()
    host_3 = dojjail.Host()

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
    host = dojjail.Host(seccomp_block=["getppid"])
    host.run()

    assert host.exec(lambda: os.getppid()) == -1
