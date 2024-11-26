from .host_mixins import *
from .host import *

class CHRootedHost(UsersMixin, CHRootMixin, PythonLibMixin, FlagMixin, DevMixin, RuntimeFSMixin, Host):
    pass

class SimpleFSHost(IPBinMixin, HostDirMixin, CHRootedHost):
    pass

class BusyBoxFSHost(BusyBoxMixin, CHRootedHost):
    pass
