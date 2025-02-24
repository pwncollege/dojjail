import logging
import multiprocessing
import os
import signal
import socket
import subprocess
import time
import weakref

from .ns import NS, new_ns, set_ns
from .net import ip_run
from .seccomp import seccomp_allow, seccomp_block
from .prctl import set_parent_death_signal
from .utils import fork_clean

HOST_UID_MAP_BASE = 100000
HOST_UID_MAP_LENGTH = 1000

PRIVILEGED_UID = 0
UNPRIVILEGED_UID = 1000

MAX_HOSTS = 100

host_pids = [ multiprocessing.Value("i", 0) for _ in range(MAX_HOSTS)]
host_target_pids = [ multiprocessing.Value("i", 0) for _ in range(MAX_HOSTS)]

class DelayedKeyboardInterrupt:
    def __enter__(self):
        self.signal_received = False
        self.old_handler = signal.signal(signal.SIGINT, self.handler)

    def handler(self, sig, frame):
        self.signal_received = (sig, frame)
        logging.debug('SIGINT received. Delaying KeyboardInterrupt.')

    def __exit__(self, exc_type, exc_value, traceback):
        signal.signal(signal.SIGINT, self.old_handler)
        if self.signal_received:
            self.old_handler(*self.signal_received)

class Host:
    _next_id = 0

    def __init__(self,
                 name=None,
                 *,
                 ns_flags=NS.ALL,
                 seccomp_allow=None,
                 seccomp_block=None,
                 persist=False,
                 privileged_uid=None,
                 unprivileged_uid=None):

        if name is None:
            name = f"Host-{Host._next_id}"

        ns_flags |= NS.USER

        self.name = name
        self.ns_flags = ns_flags
        self.seccomp_allow = seccomp_allow
        self.seccomp_block = seccomp_block

        self.id = Host._next_id
        Host._next_id += 1

        privileged_uid = privileged_uid if privileged_uid is not None else HOST_UID_MAP_BASE + self.id * HOST_UID_MAP_LENGTH + 0
        unprivileged_uid = unprivileged_uid if unprivileged_uid is not None else HOST_UID_MAP_BASE + self.id * HOST_UID_MAP_LENGTH + 1
        self._uid_map = {k: v for k, v in {PRIVILEGED_UID: privileged_uid, UNPRIVILEGED_UID: unprivileged_uid}.items() if v is not False}

        self._parent_pipe, self._child_pipe = multiprocessing.Pipe()

        self.persist = persist
        if not self.persist:
            self._finalizer = weakref.finalize(self, self.kill)

    def run(self, *, ready_event=None):
        if self.pid:
            return self

        started_event = multiprocessing.Event()
        pid = new_ns(self.ns_flags, self.uid_map)
        if pid:
            host_pids[self.id].value = pid
            started_event.wait()
            return self
        self.start()
        started_event.set()

        if ready_event:
            ready_event.wait()
        self.seccomp()
        result = self.entrypoint()
        self._child_pipe.send(result)
        os._exit(0)

    def setup_ns(self):
        if self.ns_flags & NS.UTS:
            socket.sethostname(self.name)
        if self.ns_flags & NS.PID:
            pid = fork_clean(parent_death_signal=None if self.persist else 9)
            host_target_pids[self.id] = pid
            if pid:
                with DelayedKeyboardInterrupt():
                    os.waitid(os.P_PID, pid, os.WEXITED)
                    os._exit(0)

    def setup_uid(self):
        os.setuid(PRIVILEGED_UID)
        os.setgid(PRIVILEGED_UID)
        os.setgroups([PRIVILEGED_UID])

    def setup_signal(self):
        if not self.persist:
            set_parent_death_signal()

    def setup_net(self):
        if self.ns_flags & NS.NET:
            # TODO: move away from `ip` shellout, and move this before NS.PID
            ip_run("link set lo up")

    def start(self):
        self.setup_ns()
        self.setup_uid()
        self.setup_signal()
        self.setup_net()

    def entrypoint(self):
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                pass

    def wait(self):
        os.waitpid(self.pid, 0)
        result = self._parent_pipe.recv()
        if isinstance(result, Exception):
            raise result
        return result

    def kill(self, *, signal=signal.SIGTERM):
        try:
            # This SIGTERM goes to the "waiting python process"
            os.kill(self.pid, signal)
            # Target being executed in namespaces does not exit gracefully /w SIGTERM
            os.kill(host_target_pids[self.id].value, 9)
        except ProcessLookupError:
            pass

    def enter(self, *, uid=PRIVILEGED_UID):
        assert self.pid
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
            return pid

        self.enter(uid=uid)
        self.seccomp()
        try:
            result = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            result = e
        child_pipe.send(result)
        os._exit(0)

    def exec_shell(self, cmd, uid=PRIVILEGED_UID, wait=True, attach=False, **kwargs):
        if attach:
            kwargs.setdefault("stdin", 0)
            kwargs.setdefault("stdout", 1)
            kwargs.setdefault("stderr", 2)
        else:
            kwargs.setdefault("capture_output", True)
        return self.exec((lambda: subprocess.run(cmd, shell=True, **kwargs)), uid=uid, wait=wait)

    def interactive(self, *, environ=None):
        environ = environ if environ is not None else os.environ
        shell = environ.get("SHELL", "/bin/sh")
        login_shell = "-" + shell.split("/")[-1]
        cwd = os.getcwd()
        pid = self.exec(lambda: (os.chdir(cwd), os.execve(shell, [login_shell], environ)), wait=False)
        os.waitid(os.P_PID, pid, os.WEXITED)

    @property
    def pid(self):
        return host_pids[self.id].value

    @property
    def uid_map(self):
        return self._uid_map
