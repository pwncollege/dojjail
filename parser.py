import os

import yaml

from dojjail import SimpleFSHost, Network, Host

class Parser():
    compose_file = None
    hosts = []
    network = None

    networks = {}

    def __init__(self, filename):
        with open(filename, 'r') as f:
            self.compose_file = yaml.safe_load(f)

    def _get_host(self, name):
        for host in self.hosts:
            if host.name == name:
                return host
        assert False, f"Hostname {name} not found!"

    def build(self):
        assert self.compose_file is not None, "compose_file is not set!"

        host_names = self.compose_file['services'].keys()
        network_names = self.compose_file['networks'].keys()

        # TODO: Support multiple networks and bridge routers.
        # Right now each network as its own net ns
        # So it must be simulated within one subnet
        self.network = Network("router")
        
        # Create network entries
        for network_name in network_names:
            self.networks[network_name] = []

        # Create hosts and update network access
        for hostname in host_names:
            self.hosts.append(SimpleFSHost(hostname, src_path=f"/challenge"))
            #self.hosts.append(Host(hostname))
            for net_name in self.compose_file['services'][hostname]['networks']:
                self.networks[net_name].append(hostname)

        # Connect all hosts as if they were on their own subnet
        for host_names in self.networks.values():
            for h in host_names:
                for i in host_names:
                    if h != i:
                        self.network.connect(self._get_host(h), self._get_host(i))

        # Launch challenges in each host
        self.network.run()
        for host in self.hosts:
            print(host.name)
            host.exec_shell("ping -c1 -t1 10.0.0.1")

p = Parser("../level1/docker-compose.yml")
p.build()
