import collections
import stat
import os
import multiprocessing
import socket
import signal
import subprocess
import pathlib
import tempfile
import time
import shutil
import weakref

from .ns import NS, new_ns, set_ns
from .net import ip_run, iptables_load
from .seccomp import seccomp_allow, seccomp_block
from .utils import fork_clean


HOST_UID_MAP_BASE = 100000
HOST_UID_MAP_PRIVILEGED_OFFSET = 0
HOST_UID_MAP_UNPRIVILEGED_OFFSET = 1
HOST_UID_MAP_STEP = 1000

PRIVILEGED_UID = 0
UNPRIVILEGED_UID = 1000


class Host:
    _next_id = 0

    def __init__(self, name=None, *, ns_flags=NS.ALL, seccomp_allow=None, seccomp_block=None):
        if name is None:
            name = f"Host-{Host._next_id}"

        ns_flags |= NS.USER

        self.name = name
        self.ns_flags = ns_flags
        self.seccomp_allow = seccomp_allow
        self.seccomp_block = seccomp_block

        self.id = Host._next_id
        Host._next_id += 1

        self._pid = multiprocessing.Value("i", 0)
        self._parent_pipe, self._child_pipe = multiprocessing.Pipe()

        self.runtime_path = pathlib.Path(tempfile.mkdtemp())
        os.chown(str(self.runtime_path), self.host_privileged_id, self.host_privileged_id)

        def cleanup():
            shutil.rmtree(self.runtime_path, ignore_errors=True)
            self.kill()
        self._finalizer = weakref.finalize(self, cleanup)

    def run(self):
        started_event = multiprocessing.Event()
        pid = new_ns(self.ns_flags, self.host_id_map)
        if pid:
            self._pid.value = pid
            started_event.wait()
            return
        self.start()
        started_event.set()
        self.seccomp()
        result = self.entrypoint()
        self._child_pipe.send(result)
        os._exit(0)

    def _start(self):
        if self.ns_flags & NS.UTS:
            socket.sethostname(self.name)
        if self.ns_flags & NS.PID:
            pid = fork_clean()
            if pid:
                os.waitid(os.P_PID, pid, os.WEXITED)
                os._exit(0)

        os.setuid(PRIVILEGED_UID)
        os.setgid(PRIVILEGED_UID)
        os.setgroups([PRIVILEGED_UID])

        if self.ns_flags & NS.NET:
            # TODO: move away from `ip` shellout, and move this before NS.PID
            ip_run("link set lo up")

    def start(self):
        self._start()

    def entrypoint(self):
        while True:
            time.sleep(1)

    def wait(self):
        os.waitpid(self.pid, 0)
        result = self._parent_pipe.recv()
        if isinstance(result, Exception):
            raise result
        return result

    def kill(self, *, signal=signal.SIGTERM):
        try:
            os.kill(self.pid, signal)
        except ProcessLookupError:
            pass

    def enter(self, *, uid=PRIVILEGED_UID):
        set_ns(self.pid, self.ns_flags)
        os.setuid(uid)
        os.setgid(uid)
        os.setgroups([uid])

    def seccomp(self):
        if self.seccomp_allow is not None:
            seccomp_allow(self.seccomp_allow)
        if self.seccomp_block is not None:
            seccomp_block(self.seccomp_block)

    def exec(self, fn, *, uid=PRIVILEGED_UID, wait=True):
        parent_pipe, child_pipe = multiprocessing.Pipe()
        pid = os.fork()
        if pid:
            if wait:
                os.waitid(os.P_PID, pid, os.WEXITED)
                result = parent_pipe.recv()
                if isinstance(result, Exception):
                    raise result
                return result
            return

        self.enter(uid=uid)
        self.seccomp()
        try:
            result = fn()
        except Exception as e:
            result = e
        child_pipe.send(result)
        os._exit(0)

    def exec_shell(self, cmd, **kwargs):
        return self.exec(lambda: subprocess.run(cmd, shell=True, capture_output=True), **kwargs)

    def interact(self):
        pid = os.fork()
        if pid:
            os.waitid(os.P_PID, pid, os.WEXITED)
            return
        self.enter()
        os.execve("/usr/bin/bash", ["/usr/bin/bash", "-i"], os.environ)

    @property
    def pid(self):
        return self._pid.value

    @property
    def host_base_id(self):
        return HOST_UID_MAP_BASE + self.id * HOST_UID_MAP_STEP

    @property
    def host_privileged_id(self):
        return self.host_base_id + HOST_UID_MAP_PRIVILEGED_OFFSET

    @property
    def host_unprivileged_id(self):
        return self.host_base_id + HOST_UID_MAP_UNPRIVILEGED_OFFSET

    @property
    def host_id_map(self):
        return (
            f"{PRIVILEGED_UID} {self.host_privileged_id} 1\n"
            f"{UNPRIVILEGED_UID} {self.host_unprivileged_id} 1\n"
        )


class Network(Host):
    def __init__(self, *args, **kwargs):
        hosts = kwargs.pop("hosts", [])
        super().__init__(*args, **kwargs, ns_flags=(NS.NET | NS.UTS))

        self.host_ips = {}
        self.host_edges = collections.defaultdict(set)
        self._next_ip = 1
        for host in hosts:
            self.dhcp(host)

    @property
    def hosts(self):
        return self.host_ips.keys()

    def dhcp(self, host):
        if host not in self.host_ips:
            assert self._next_ip < 255
            self.host_ips[host] = f"10.0.0.{self._next_ip}"
            self._next_ip += 1
        return self.host_ips[host]

    def connect(self, host1, host2):
        self.dhcp(host1)
        self.dhcp(host2)
        self.host_edges[host1].add(host2)
        self.host_edges[host2].add(host1)

    @property
    def host_id_map(self):
        host_mappings = "".join(f"{host.host_base_id} {host.host_base_id} {HOST_UID_MAP_STEP}\n" for host in self.hosts)
        return f"{PRIVILEGED_UID} {PRIVILEGED_UID} 1\n" + host_mappings

    def start(self):
        super().start()

        ip_run("link add name bridge0 type bridge")

        for host, host_ip in self.host_ips.items():
            ip_run(f"link add veth{host.id} type veth peer name veth{host.id}-child")
            ip_run(f"link set veth{host.id} master bridge0")
            host.run()
            ip_run(f"link set veth{host.id} up")
            ip_run(f"link set veth{host.id}-child netns {host.pid}")
            # TODO: host `ip_run` before chroot
            host.exec(lambda: (ip_run(f"link set veth{host.id}-child name eth0"),
                               ip_run(f"addr add {host_ip}/24 dev eth0"),
                               ip_run("link set eth0 up")))

        iptables_rules = [
            "*filter",
            ":INPUT ACCEPT [0:0]",
            ":FORWARD DROP [0:0]",
            ":OUTPUT ACCEPT [0:0]",
        ]
        for src_host, dst_hosts in self.host_edges.items():
            for dst_host in dst_hosts:
                src_ip = self.host_ips[src_host]
                dst_ip = self.host_ips[dst_host]
                iptables_rules.append(f"-A FORWARD -s {src_ip}/32 -d {dst_ip}/32 -j ACCEPT")
        iptables_rules.append("COMMIT")
        iptables_rules.append("")
        iptables_load("\n".join(iptables_rules))

        ip_run("link set bridge0 up")


class SimpleFSHost(Host):


    def __init__(self, *args, **kwargs):
        self.src_path = pathlib.Path(kwargs.pop("src_path"))

        syscall_blocks = kwargs.pop("syscall_blocks", [])
        syscall_blocks.append("chroot")
        kwargs["syscall_blocks"] = syscall_blocks

        super().__init__(*args, **kwargs)

    @property
    def fs_path(self):
        return self.runtime_path / "fs"

    def create_users(self):
        os.mknod("/dev/null", 0o666)

        os.mkdir("/home/user")
        os.chown("/home/user", UNPRIVILEGED_UID, UNPRIVILEGED_UID)

        with open("/etc/passwd", "w") as f:
            f.write("".join(f"{user}\n" for user in [
                f"root:x:{PRIVILEGED_UID}:{PRIVILEGED_UID}:root:/root:/bin/sh",
                f"user:x:{UNPRIVILEGED_UID}:{UNPRIVILEGED_UID}:user:/home/user:/bin/sh",
                f"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            ]))

        with open("/etc/group", "w") as f:
            f.write("".join(f"{group}\n" for group in [
                f"root:x:{PRIVILEGED_UID}:",
                f"user:x:{UNPRIVILEGED_UID}:",
                f"nobody:x:65534:",
            ]))

    def start(self):
        self._start()

        shutil.copytree(self.src_path, self.fs_path, symlinks=True)

        for path_name in ["bin", "sbin", "usr", "root", "home", "etc", "tmp", "dev"]:
            path = self.fs_path / path_name
            path.mkdir(exist_ok=True)

        os.chroot(self.fs_path)  # TODO: seccomp away chroot
        os.chdir("/")

        self.create_users()

    def enter(self, *args, **kwargs):
        super().enter(*args, **kwargs)
        os.chroot(self.fs_path)
        os.chdir("/")



class BusyBoxFSHost(SimpleFSHost):
    _flag_val = ""

    def __init__(self, *args, **kwargs):
        self.src_path = pathlib.Path(kwargs.get("src_path"))
        with open ("/flag", 'r') as f:
            self._flag_val = f.read()
        super().__init__(*args, **kwargs)

    def start(self):
        self._start()

        shutil.copytree(self.src_path, self.fs_path, symlinks=True)

        for path_name in ["bin", "sbin", "usr", "root", "home", "etc", "tmp", "dev", "usr/bin", "usr/sbin"]:
            path = self.fs_path / path_name
            path.mkdir(exist_ok=True)

        # Make a barebones sane file system
        shutil.copytree("/usr/lib/python3.8", self.fs_path / "usr/lib/python3.8", symlinks=True)
        # TODO: Remove and statically compile all bins?
        shutil.copytree("/lib/x86_64-linux-gnu", self.fs_path / "lib/x86_64-linux-gnu", symlinks=True)
        shutil.copytree("/lib64", self.fs_path / "lib64", symlinks=True)

        os.chroot(self.fs_path)  # TODO: seccomp away chroot
        os.chdir("/")

        try:
            subprocess.run(["/busybox", "--install"], capture_output=True)
        except subprocess.CalledProcessError as e:
            raise Exception(e.stderr)

        self.create_users()

        if self.name == 'flag_host':
            with open ("/flag", 'w') as f:
                f.write(self._flag_val)
        self_flag_val = ""
