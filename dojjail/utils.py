import os
import pathlib
import random

from .prctl import set_parent_death_signal


def fork_clean(parent_death_signal=9):
    pid = os.fork()
    if not pid and parent_death_signal is not None:
        set_parent_death_signal(parent_death_signal)
    return pid


def sbin_which(program):
    for dir in ["/sbin", "/usr/sbin"]:
        path = pathlib.Path(dir, program)
        if path.exists():
            return str(path)
    else:
        raise Exception(f"`{program}` not found")


def interact(self):
    from .host import PRIVILEGED_UID, UNPRIVILEGED_UID
    hostname = input("Which host would you like to interact with? ")
    try:
        host = next(h for h in self.hosts if h.name == hostname)
        uid = PRIVILEGED_UID if input("Launch root shell (y/N)? ").lower() == "y" else UNPRIVILEGED_UID
        host.interact(uid=uid)
    except StopIteration:
        print("No such host!")


def describe_network(network, ip_filter=lambda h: True):
    s  = f"Network {network.name}:\n"
    for host in network.hosts:
        ip = network.host_ips[host] if ip_filter(host) else "HIDDEN"
        s += f"- Host {host.name}, IP {ip}\n"
    return s.rstrip()


def describe_network_connections(network):
    for src_host, dst_hosts in network.host_edges.items():
        for dst_host in dst_hosts:
            print(f"{src_host.name} {network.host_ips[src_host]} <-> {network.host_ips[dst_host]} {dst_host.name}")


def generate_linear_network(network, host_list, start, end, min_len=4, max_len=8):
    prev_host = start

    length = random.randint(min_len, max_len)
    for _ in range(length):
        selected_host = host_list[random.randint(0, len(host_list))].copy()
        network.connect(prev_host, selected_host, randomize=True)
        prev_host = selected_host
    network.connect(prev_host, end)


def generate_random_network(network, host_list, size, start, end, min_depth=4):
    assert size > min_depth

    depth = random.randint(min_depth, size)
    network.generate_linear_network(host_list, start, end, min_len=depth, max_len=depth)

    rand_node_cnt = size - depth

    for _ in range(rand_node_cnt):
        selected_src = list(network.host_edges.keys())[random.randint(0, len(network.host_edges))]
        selected_dest = host_list[random.randint(0, len(host_list))].copy()
        network.connect(selected_src, selected_dest, randomize=True)
