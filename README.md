# dojjail

*dojjail* is a simple python framework for running complex namespace configurations.
Think something like docker, but with a super simple implementation, and python library interface instead of command line interface.

# Usage

You can spin up a host this simply:

```python
In [1]: import os
   ...: from dojjail import Host
   ...:
   ...: host = Host("host-1")
   ...: host.run()
   ...:
   ...: host.exec(lambda: os.system("hostname; whoami; ip a"))

host-1
root
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
```

You can also spin up a network of hosts:

```python
In [1]: import os
   ...: from dojjail import Host, Network
   ...:
   ...: host_1 = Host("host-1")
   ...: host_2 = Host("host-2")
   ...:
   ...: network = Network("router")
   ...: network.connect(host_1, host_2)
   ...:
   ...: network.run()
   ...:
   ...: host_1.exec(lambda: os.system("ping -c 3 10.0.0.2"))

PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.073 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.047 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.056 ms
```

The important thing to realize with these `Host.exec`s is that you are running arbitrary *python* code.

This means, for example, you can write python to orchestrate the interaction of various hosts, all within python:

```python
   ...: import requests
   ...: from flask import Flask
   ...: from dojjail import Host, Network
   ...:
   ...: app = Flask(__name__)
   ...:
   ...: @app.route("/")
   ...: def hello_world():
   ...:     return "Hello, World!"
   ...:
   ...: class WebServerHost(Host):
   ...:     def entrypoint(self):
   ...:         app.run("0.0.0.0", 80)
   ...:
   ...: server_host = WebServerHost("web-server")
   ...: client_host = Host("web-client")
   ...:
   ...: network = Network("router")
   ...: network.connect(server_host, client_host)
   ...:
   ...: network.run()
   ...:
   ...: response = client_host.exec(lambda: requests.get("http://10.0.0.1/"))
   ...: print(response.text)

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

## Docker

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

### Seccomp Filter

In particular, the system calls we need access to, which docker does not normally allow, are:
- unshare (create namespaces, think `docker run`)
- setns (join an already created, think `docker exec`)
- sethostname (set the hostname within a namespace, think `docker run --hostname=...`)

You can create a custom seccomp filter which just unblocks these system calls, as the above usage example does.

In theory, unblocking these system calls *should not be dangerous*.
We do not need `CAP_SYS_ADMIN`, because we take advantage of user namespaces to gain capabilities within the context of the user namespace.
This then allows us to create more namespaces, like for example, a network namespace, in which we have `CAP_NET_ADMIN`, and therefore can configure network interfaces (something not normally possible within an unprivileged docker container).

The security model of user namespaces within Linux suggests that this *should be safe* (untrusted code cannot escape to the host).
However, various CVEs surrounding namespaces suggest that it's a dangerous code base, ripe with future unknown vulnerabilities.
Probably, we will one day live in a future where user namespaces are allowed by default within docker.
But that world does not yet exist, good luck.
