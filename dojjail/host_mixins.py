import contextlib
import pathlib
import subprocess
import shutil
import sys
import os
import tempfile

from .host import PRIVILEGED_UID, UNPRIVILEGED_UID
from .utils import sbin_which

class RuntimeFSMixin:
    def __init__(self, *args, **kwargs):
        self.fs_path = pathlib.Path(tempfile.mkdtemp())
        super().__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        self.setup_fs()
        super().run(*args, **kwargs)

    def setup_fs(self):
        self.fs_path.mkdir(exist_ok=True)

    def kill(self, *args, **kwargs):
        shutil.rmtree(self.fs_path, ignore_errors=True)
        super().kill(*args, **kwargs)

class LSBMixin(RuntimeFSMixin):
    def setup_fs(self):
        super().setup_fs()

        for path_name in ["bin", "sbin", "usr", "root", "home", "dev", "etc", "tmp", "usr/bin", "usr/sbin"]:
            path = self.fs_path / path_name
            path.mkdir(exist_ok=True)

class DevMixin(RuntimeFSMixin):
    def setup_fs(self):
        super().setup_fs()

        os.makedirs(self.fs_path / "dev", exist_ok=True)
        os.mknod(self.fs_path / "dev/null", 0o666)
        os.chmod(self.fs_path / "dev/null", 0o666)

class HostLibsMixin(RuntimeFSMixin):
    def setup_fs(self):
        super().setup_fs()
        shutil.copytree("/lib/x86_64-linux-gnu", self.fs_path / "lib/x86_64-linux-gnu", symlinks=True)
        shutil.copytree("/lib64", self.fs_path / "lib64", symlinks=True)

class PythonLibMixin(HostLibsMixin):
    def setup_fs(self):
        super().setup_fs()

        # Make a barebones sane file system
        #for p in [ f"/usr/lib/python3.{sys.version_info.minor}", "/usr/lib/python3" ]: # python3 is very large, and 3.12 seems to work
        for p in [ f"/usr/lib/python3.{sys.version_info.minor}" ]:
            if os.path.exists(p) and p.startswith("/usr/lib"):
                shutil.copytree(p, self.fs_path / p.lstrip("/"), symlinks=True)

class FlagMixin(RuntimeFSMixin):
    def __init__(self, *args, flag_source=None, **kwargs):
        self._flag_source = flag_source
        super().__init__(*args, **kwargs)

    def setup_fs(self):
        super().setup_fs()

        # backwards compatibility
        if self.name == "flag_host" and not self._flag_source:
            self._flag_source = "/flag"

        if self._flag_source:
            with open(self.fs_path / "flag", "w") as o, open(self._flag_source) as i:
                o.write(i.read())

class HostDirMixin(RuntimeFSMixin):
    def __init__(self, src_path, *args, **kwargs):
        self.src_path = src_path
        super().__init__(*args, **kwargs)

    def setup_fs(self):
        super().setup_fs()
        shutil.copytree(self.src_path, self.fs_path, symlinks=True, dirs_exist_ok=True)
        os.chmod(self.fs_path, 0o755)

class CHRootMixin(RuntimeFSMixin):
    def __init__(self, *args, **kwargs):
        seccomp_block = kwargs.pop("seccomp_block", [])
        seccomp_block.append("chroot")
        super().__init__(*args, seccomp_block=seccomp_block, **kwargs)

    @contextlib.contextmanager
    def tmp_chroot_ctx(self):
        real_root = os.open("/", 0)
        old_cwd = os.getcwd()
        try:
            os.chroot(self.fs_path)
            os.chdir("/")
            yield
        finally:
            os.fchdir(real_root)
            os.chroot(".")
            os.chdir(old_cwd)
            os.close(real_root)

    # hooking to chroot before we drop privs
    def setup_uid(self, *args, **kwargs):
        os.chroot(self.fs_path)
        os.chdir("/")
        super().setup_uid(*args, **kwargs)

    def enter(self, *args, **kwargs):
        super().enter(*args, **kwargs)
        os.chroot(self.fs_path)
        os.chdir("/")

class UsersMixin(CHRootMixin):
    def setup_fs(self):
        super().setup_fs()

        with self.tmp_chroot_ctx():
            os.makedirs("/home/user", exist_ok=True)
            os.makedirs("/etc", exist_ok=True)
            os.chown("/home/user", UNPRIVILEGED_UID, UNPRIVILEGED_UID)

            with open("/etc/passwd", "w") as f:
                f.write("".join(f"{user}\n" for user in [
                    f"root:x:{PRIVILEGED_UID}:{PRIVILEGED_UID}:root:/root:/bin/sh",
                    f"user:x:{UNPRIVILEGED_UID}:{UNPRIVILEGED_UID}:user:/home/user:/bin/sh",
                    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
                ]))

            with open("/etc/group", "w") as f:
                f.write("".join(f"{group}\n" for group in [
                    f"root:x:{PRIVILEGED_UID}:",
                    f"user:x:{UNPRIVILEGED_UID}:",
                    "nobody:x:65534:",
                ]))

class BusyBoxMixin(CHRootMixin, LSBMixin):
    def setup_fs(self):
        super().setup_fs()

        shutil.copy2("/usr/bin/busybox", self.fs_path / "busybox")
        with self.tmp_chroot_ctx():
            subprocess.run(["/busybox", "--install"], check=True, capture_output=True)
            subprocess.run(["/busybox", "--install", "bin"], check=True, capture_output=True)
            os.unlink("/busybox")

    def interact(self, **kwargs):
        self.exec_shell("/bin/env -i /bin/sh -i", attach=True, **kwargs)

class IPBinMixin(HostLibsMixin):
    def setup_fs(self):
        super().setup_fs()

        # we shell out to ip to set up networking
        ip_path = sbin_which("ip")
        os.makedirs(self.fs_path / "sbin", exist_ok=True)
        shutil.copy2(ip_path, self.fs_path / "sbin")
