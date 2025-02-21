import multiprocessing
import subprocess
import sys

from .ns import NS
from .net import ip_run, iptables_load
from .host import Host, PRIVILEGED_UID


if b"br_netfilter" not in subprocess.run(["/sbin/lsmod"], capture_output=True, check=True).stdout:
    print("WARNING: 'br_netfilter' kernel module is not loaded. Network filtering with NOT work.", file=sys.stderr)


class Network(Host):
    def __init__(self, *args, **kwargs):
        subnet = kwargs.pop("subnet", "10.0.0.0/24")
        hosts = kwargs.pop("hosts", [])

        super().__init__(*args, **kwargs, ns_flags=(NS.NET | NS.UTS))

        self.subnet = subnet

        self.host_ips = { }
        self.host_edges = { }

        if not isinstance(hosts, dict):
            hosts = {host: None for host in hosts}

        for host, ip in hosts.items():
            self.assign_ip_address(host, ip)
            self.host_edges[host] = set(other_host for other_host in hosts if other_host is not host)

    def assign_ip_address(self, host, ip=None):
        if host in self.host_ips:
            raise RuntimeError("Host `{host}` requested IP address `{ip}`, but already has IP address `{self.host_ips[host]}`")

        if ip is not None:
            existing_host_with_ip = next((host for host, host_ip in self.host_ips.items() if host_ip == ip), None)
            if existing_host_with_ip is not None:
                raise RuntimeError("Host `{host}` requested IP address `{ip}` already in use by `{existing_host_with_ip}`")
            self.host_ips[host] = ip
        else:
            try:
                ip = next(ip for ip in self.subnet_ip_range if ip not in self.host_ips.values())
            except StopIteration:
                raise RuntimeError("No more IP addresses available")
            self.host_ips[host] = ip

        return self.host_ips[host]

    def connect(self, host1, host2):
        self.assign_ip_address(host1)
        self.assign_ip_address(host2)
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
                               ip_run(f"addr add {host_ip}/{self.subnet_mask} dev eth0"),
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
    def subnet_mask(self):
        return int(self.subnet.split("/")[1])

    @property
    def subnet_ip_range(self):
        for ip in self.subnet_int_ip_range:
            yield self.int_to_ip(ip)

    @property
    def subnet_int_ip_range(self):
        base_ip, mask = self.subnet.split("/")
        base_ip = self.ip_to_int(base_ip)
        mask = int(mask)
        return range(base_ip, base_ip + (1 << (32 - mask)))

    @staticmethod
    def ip_to_int(ip):
        return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(ip.split("."))))

    @staticmethod
    def int_to_ip(ip):
        return f"{ip >> 24 & 0xFF}.{ip >> 16 & 0xFF}.{ip >> 8 & 0xFF}.{ip & 0xFF}"

    @property
    def hosts(self):
        return self.host_ips.keys()

    @property
    def uid_map(self):
        return {
            **{user_id: user_id for host in self.hosts for user_id in host.uid_map.values()},
            PRIVILEGED_UID: PRIVILEGED_UID,
        }
