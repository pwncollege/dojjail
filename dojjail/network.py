import multiprocessing
import subprocess
import random
import sys

from .ns import NS
from .net import ip_run, iptables_load
from .host import Host, PRIVILEGED_UID, UNPRIVILEGED_UID

class Network(Host):
    def __init__(self, *args, **kwargs):
        hosts = kwargs.pop("hosts", [])
        super().__init__(*args, **kwargs, ns_flags=(NS.NET | NS.UTS))

        self.host_ips = { }
        self.host_edges = { }
        self._next_ip = 1
        self._available_ips = list(range(255))
        for host in hosts:
            self.dhcp(host)
            self.host_edges[host] = set(other_host for other_host in hosts if other_host is not host)

        if b"br_netfilter" not in subprocess.run(["/sbin/lsmod"], capture_output=True, check=True).stdout:
            print("WARNING: 'br_netfilter' kernel module is not loaded. Network filtering with NOT work.", file=sys.stderr)

    def describe(self, ip_filter=lambda h: True):
        s  = f"Network {self.name}:\n"
        for host in self.hosts:
            ip = self.host_ips[host] if ip_filter(host) else "HIDDEN"
            s += f"- Host {host.name}, IP {ip}\n"
        return s.rstrip()

    def interact(self, *, uid=PRIVILEGED_UID):
        hostname = input("Which host would you like to interact with? ")
        try:
            host = next(h for h in self.hosts if h.name == hostname)
            uid = PRIVILEGED_UID if input("Launch root shell (y/N)? ").lower() == "y" else UNPRIVILEGED_UID
            host.interact(uid=uid)
        except StopIteration:
            print("No such host!")

    def print_adj_list(self):
         for src_host, dst_hosts in self.host_edges.items():
             for dst_host in dst_hosts:
                 print(f"{src_host.name} {self.host_ips[src_host]} <-> {self.host_ips[dst_host]} {dst_host.name}")
         super().run()

    def _random_ip(self):
        selected_ip = random.randint(0, len(self._available_ips))
        self._available_ips.remove(selected_ip)
        return selected_ip

    def dhcp(self, host, randomize=False):
        if randomize:
            assert self._next_ip == 1
            self.host_ips[host] = f"10.0.0.{self._random_ip()}"
            return self.host_ips[host]
        else:
            if host not in self.host_ips:
                assert self._next_ip < 255
                self.host_ips[host] = f"10.0.0.{self._next_ip}"
                self._next_ip += 1
            return self.host_ips[host]

    def connect(self, host1, host2, randomize=False):
        self.dhcp(host1, randomize=False)
        self.dhcp(host2, randomize=False)
        self.host_edges.setdefault(host1, set()).add(host2)
        self.host_edges.setdefault(host2, set()).add(host1)
        return self

    def setup_iptables(self):
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

    def setup_hosts(self, *args, **kwargs):
        for host, host_ip in self.host_ips.items():
            if ip_run(f"link show veth{host.id}", check=False).stdout:
                continue

            ip_run(f"link add veth{host.id} type veth peer name veth{host.id}-child")
            ip_run(f"link set veth{host.id} master bridge0")
            host.run(*args, **kwargs)
            ip_run(f"link set veth{host.id} up")
            ip_run(f"link set veth{host.id}-child netns {host.pid}")
            # TODO: host `ip_run` before chroot
            host.exec(lambda: (ip_run(f"link set veth{host.id}-child name eth0"),
                               ip_run(f"addr add {host_ip}/24 dev eth0"),
                               ip_run("link set eth0 up")))

    def start(self):
        super().start()
        network_ready_event = multiprocessing.Event()
        ip_run("link add name bridge0 type bridge")
        self.setup_iptables()
        self.setup_hosts(ready_event=network_ready_event)
        ip_run("link set bridge0 up")
        network_ready_event.set()

    @property
    def hosts(self):
        return self.host_ips.keys()

    @property
    def uid_map(self):
        return {
            **{user_id: user_id for host in self.hosts for user_id in host.uid_map.values()},
            PRIVILEGED_UID: PRIVILEGED_UID,
        }

    def generate_linear_network(self, host_list, start, end, min_len=4, max_len=8):
        prev_host = start

        length = random.randint(min_len, max_len)
        for _ in range(length):
            selected_host = host_list[random.randint(0, len(host_list))].copy()
            self.connect(prev_host, selected_host, randomize=True)
            prev_host = selected_host
        self.connect(prev_host, end)

    def generate_random_network(self, host_list, size, start, end, min_depth=4):
        assert size > min_depth

        depth = random.randint(min_depth, size)
        self.generate_linear_network(host_list, start, end, min_len=depth, max_len=depth)

        rand_node_cnt = size - depth

        for _ in range(rand_node_cnt):
            selected_src = list(self.host_edges.keys())[random.randint(0, len(self.host_edges))]
            selected_dest = host_list[random.randint(0, len(host_list))].copy()
            self.connect(selected_src, selected_dest, randomize=True)
