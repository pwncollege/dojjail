import collections
import os
import multiprocessing
import pickle
import socket
import signal
import subprocess
import pathlib
import tempfile
import time
import shutil
import ctypes


CLONE_NEWNS       = 0x00020000 # New mount namespace group
CLONE_NEWCGROUP   = 0x02000000 # New cgroup namespace
CLONE_NEWUTS      = 0x04000000 # New utsname namespace
CLONE_NEWIPC      = 0x08000000 # New ipc namespace
CLONE_NEWUSER     = 0x10000000 # New user namespace
CLONE_NEWPID      = 0x20000000 # New pid namespace
CLONE_NEWNET      = 0x40000000 # New network namespace

SCMP_ACT_ALLOW	  = 0x7fff0000

PR_SET_PDEATHSIG  = 1

HOST_UID_MAP_BASE = 100000
HOST_UID_MAP_PRIVILEGED_OFFSET = 0
HOST_UID_MAP_UNPRIVILEGED_OFFSET = 1
HOST_UID_MAP_STEP = 1000

PRIVILEGED_UID = 0
UNPRIVILEGED_UID = 1000

libc = ctypes.CDLL("libc.so.6")
libseccomp = ctypes.CDLL("libseccomp.so.2")


def new_user_ns(ns_flags=0, uid_map=None):
    if uid_map is None:
        uid_map = f"{PRIVILEGED_UID} {os.getuid()} 1\n"
    unshare_semaphore = multiprocessing.Semaphore(0)
    id_map_semaphore = multiprocessing.Semaphore(0)
    pid = os.fork()
    if pid:
        unshare_semaphore.acquire()
        for path in [f"/proc/{pid}/uid_map", f"/proc/{pid}/gid_map"]:
            with open(path, "w") as f:
                f.write(uid_map)
        id_map_semaphore.release()
    else:
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
        libc.unshare(CLONE_NEWUSER | ns_flags)
        unshare_semaphore.release()
        id_map_semaphore.acquire()
    return pid


def sbin_which(program):
    for dir in ["/sbin", "/usr/sbin"]:
        path = pathlib.Path(dir, program)
        if path.exists():
            return path
    else:
        raise Exception(f"`{program}` not found")


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


def seccomp_block(syscalls):
    libseccomp.seccomp_init(0)


class Host:
    _next_id = 0

    def __init__(self, name, *, ns_flags=None):
        self.name = name
        if ns_flags is None:
            ns_flags = (
                CLONE_NEWNS |
                CLONE_NEWCGROUP |
                CLONE_NEWUTS |
                CLONE_NEWIPC |
                CLONE_NEWPID |
                CLONE_NEWNET
            )
        self.ns_flags = ns_flags

        self.id = Host._next_id
        Host._next_id += 1

        self._pid = multiprocessing.Value("i", 0)

        self.runtime_path = tempfile.TemporaryDirectory()
        os.chown(self.runtime_path.name, self.host_privileged_id, self.host_privileged_id)
        # TODO: make runtime_path deletion not be a disaster on Exception

    def run(self):
        started_semaphore = multiprocessing.Semaphore(0)
        pid = new_user_ns(self.ns_flags, self.host_id_map)
        if pid:
            self._pid.value = pid
            started_semaphore.acquire()
            return
        self.start()
        started_semaphore.release()
        self.entrypoint()

    def start(self):
        if self.ns_flags & CLONE_NEWPID:
            if os.fork():
                os.wait()
                os._exit(0)
            libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)

        os.setuid(PRIVILEGED_UID)
        os.setgid(PRIVILEGED_UID)
        os.setgroups([PRIVILEGED_UID])

        if self.ns_flags & CLONE_NEWUTS:
            socket.sethostname(self.name)

        if self.ns_flags & CLONE_NEWNET:
            ip_run("link set lo up")

    def entrypoint(self):
        while True:
            time.sleep(1)

    def enter(self, *, uid=PRIVILEGED_UID):
        ns_names ={
            CLONE_NEWUSER: "user",
            CLONE_NEWNS: "mnt",
            CLONE_NEWCGROUP: "cgroup",
            CLONE_NEWUTS: "uts",
            CLONE_NEWIPC: "ipc",
            CLONE_NEWPID: "pid_for_children",
            CLONE_NEWNET: "net",
        }
        for ns_flag, ns_name in ns_names.items():
            if ns_flag & (CLONE_NEWUSER | self.ns_flags):
                ns_path = f"/proc/{self.pid}/ns/{ns_name}"
                assert libc.setns(os.open(ns_path, 0), 0) == 0, ns_path

        os.setuid(uid)
        os.setgid(uid)
        os.setgroups([uid])

    def exec(self, fn, *, uid=PRIVILEGED_UID):
        parent_pipe, child_pipe = multiprocessing.Pipe()
        pid = os.fork()
        if pid:
            os.wait()
            return pickle.loads(parent_pipe.recv_bytes())
        self.enter(uid=uid)
        result = fn()
        child_pipe.send_bytes(pickle.dumps(result))
        os._exit(0)

    def exec_shell(self, cmd, **kwargs):
        return self.exec(lambda: subprocess.run(cmd, shell=True, capture_output=True), **kwargs)

    @property
    def pid(self):
        return self._pid.value

    @property
    def host_privileged_id(self):
        return (HOST_UID_MAP_BASE +
                self.id * HOST_UID_MAP_STEP +
                HOST_UID_MAP_PRIVILEGED_OFFSET)

    @property
    def host_unprivileged_id(self):
        return (HOST_UID_MAP_BASE +
                self.id * HOST_UID_MAP_STEP +
                HOST_UID_MAP_UNPRIVILEGED_OFFSET)

    @property
    def host_id_map(self):
        return (
            f"{PRIVILEGED_UID} {self.host_privileged_id} 1\n"
            f"{UNPRIVILEGED_UID} {self.host_unprivileged_id} 1\n"
        )


class Network(Host):
    def __init__(self, *args, **kwargs):
        hosts = kwargs.pop("hosts", [])
        super().__init__(*args, **kwargs, ns_flags=CLONE_NEWNET|CLONE_NEWUTS)

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
        uid_map_range = HOST_UID_MAP_STEP * (len(self.hosts) + 1)
        return (
            f"{PRIVILEGED_UID} {os.getuid()} 1\n"
            f"{HOST_UID_MAP_BASE} {HOST_UID_MAP_BASE} {uid_map_range}\n"
        )

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

    def entrypoint(self):
        while True:
            time.sleep(1)


class SimpleFSHost(Host):
    def __init__(self, *args, **kwargs):
        self.src_path = pathlib.Path(kwargs.pop("src_path"))
        super().__init__(*args, **kwargs)

    @property
    def fs_path(self):
        return pathlib.Path(self.runtime_path.name) / "fs"

    def start(self):
        super().start()

        shutil.copytree(self.src_path, self.fs_path, symlinks=True)

        for path_name in ["bin", "sbin", "usr", "root", "home", "etc", "tmp", "dev"]:
            path = self.fs_path / path_name
            path.mkdir(exist_ok=True)

        os.chroot(self.fs_path)  # TODO: seccomp away chroot
        os.chdir("/")

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

    def enter(self, *args, **kwargs):
        super().enter(*args, **kwargs)
        os.chroot(self.fs_path)  # TODO: seccomp away chroot
        os.chdir("/")
