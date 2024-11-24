# dojjail

*dojjail* is a simple python framework for running complex namespace configurations.
Think something like docker, but which looks more like `subprocess.run` than `docker run`.

# Usage

## `dojjail.Host`

You can spin up a host this simply:

```python
import os
from dojjail import Host

host = Host("host-1")
host.run()

host.exec(lambda: os.system("hostname; whoami; ip a"))
```
```
host-1
root
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
```

## `dojjail.Network`

You can also spin up a network of hosts:

```python
import os
from dojjail import Host, Network

host_1 = Host("host-1")
host_2 = Host("host-2")

network = Network("router")
network.connect(host_1, host_2)

network.run()

result = host_1.exec_shell("ping -c 3 10.0.0.2")
print(result.stdout.decode())
```
```
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.073 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.047 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.056 ms
```

Notice that in this case we used `Host.exec_shell` instead of `Host.exec`.
If all you're interested in running is a shell command, `Host.exec_shell` is a simple wrapper around `Host.exec` which uses `subprocess.run` to return a `subprocess.CompletedProcess`.

## `dojjail.Host.entrypoint`

The important thing to realize with these `Host.exec`s is that you are running arbitrary *python* code.
This means, we are not restricted to just running shell commands like above.

For example, you can write python to orchestrate the interaction of various hosts, all without leaving python:

```python
 import requests
 from flask import Flask
 from dojjail import Host, Network

 app = Flask(__name__)

 @app.route("/")
 def hello_world():
     return "Hello, World!"

 class WebServerHost(Host):
     def entrypoint(self):
         app.run("0.0.0.0", 80)

 server_host = WebServerHost("web-server")
 client_host = Host("web-client")

 network = Network("router")
 network.connect(server_host, client_host)

 network.run()

 response = client_host.exec(lambda: requests.get("http://10.0.0.1/"))
 print(response.text)
```
```
 * Serving Flask app '__main__'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://127.0.0.1:80
Press CTRL+C to quit
10.0.0.2 - - [21/Apr/2023 00:27:16] "GET / HTTP/1.1" 200 -
Hello, World!
```

In this case, we need to override the default `Host.entrypoint` (which is just `while True: time.sleep(1)`).
This is because `Host.exec` is syncronous (as in you can't just run two `Host.exec`s at once), and so we would need to multiprocess or multithread in order to achieve two simultaneous `Host.exec`s.
Or, we could just override `Host.entrypoint`, as is done here, since that is already in a separate process (specifically, it is the pid 1 of that host's PID namespace).

# Dockerfile

First, build the docker image:
```sh
docker build -t dojjail .
```

Then, run the docker image, with a less restricted seccomp filter:
```sh
docker run \
    --rm \
    --security-opt seccomp=<(wget -qO - "https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json" | jq '.syscalls += [{"names": ["unshare", "setns", "sethostname"], "action": "SCMP_ACT_ALLOW"}]') \
    dojjail
```

Alternatively, if you're feeling more dangerous, just run entirely without seccomp:
```sh
docker run \
    --rm \
    --security-opt seccomp=unconfined \
    dojjail
```

## Seccomp Filter

In particular, the system calls we need access to, which docker does not normally allow, are:
- `unshare` (create namespaces, think `docker run`)
- `setns` (join an already created namespace, think `docker exec`)
- `sethostname` (set the hostname within a namespace, think `docker run --hostname=...`)

You can create a custom seccomp filter which just unblocks these system calls, as the above usage example does.

In theory, unblocking these system calls *should not be dangerous*.
We do not need `CAP_SYS_ADMIN`, because we take advantage of user namespaces to gain capabilities within the context of the user namespace.
This then allows us to create more namespaces, like for example, a network namespace, in which we have `CAP_NET_ADMIN`, and therefore can configure network interfaces (something not normally possible within an unprivileged docker container).

The security model of user namespaces within Linux suggests that this *should be safe* (untrusted code cannot escape to the host).
However, various CVEs surrounding namespaces suggest that it's a dangerous code base, ripe with future unknown vulnerabilities.
Probably, we will one day live in a future where user namespaces are allowed by default within docker.
But that world does not yet exist, good luck.


# Implementation

## Namespaced Process Tree

```
init namespace:
                 run() --- new_ns() --------- ... --------------------------- exec(fn) ------------------ ...
                              |                                                 |
                              |                                               enter()
                              |                                                 |
                           unshare()                                          set_ns()
==============================|=================================================|============================
Host namespace:               |                                                 |
                              --- start() --- wait() --- exit()                 |
                                          |                                     |
pid 1:                                    --- seccomp() --- entrypoint()        |
                                                                                |
                                                                                |
                                                                                --- seccomp() -- fn()
```

- `Host.run()` is called to begin the new `Host` life cycle
- This in turn calls `new_ns()`, which `fork()`s
- The parent process waits for the `Host` to finish initializing
- The child process calls `unshare()` to create a new namespace, and then initializes the new `Host` namespace by calling `Host.start()`, which `fork()`s
- The parent process (in the new `Host` namespace) `wait()`s for the child process to die, and then `exit()`s
- The child process (in the new `Host` namespace) is now `pid 1`, since it is the child of a `unshare(PID) ... fork()`, and calls `Host.seccomp()` and `Host.entrypoint()`
- Once the `Host` has finished initializing, the initial process is able to resume and may call `Host.exec(fn)`, which `fork()`s
- The parent process waits for `fn()` to finish executing
- The child process calls `Host.enter()`, which calls `set_ns()` to enter the `Host`s namespace, and then calls `Host.seccomp()` and `fn()`

# Notes

You **MUST** have the `br_netfilter` kernel module loaded for network filtering to work, otherwise packets get bridged directly between network hosts and iptables never sees it to restrict connections.
