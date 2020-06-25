# DNSrebinder

DNSrebinder is a python script to run a DNS server. It is used to test for DNS rebinding attacks. 

Usage help:
```bash
$ python3 dnsrebinder.py -h
usage: dnsrebinder.py [-h] [--port PORT] [--tcp] [--udp] [--domain DOMAIN]
                     [--ttl TTL] [--ip IP] [--rebind REBIND]
                     [--counter COUNTER]

Start a DNS implemented in Python. Usually DNSs use UDP on port 53.

optional arguments:
  -h, --help         show this help message and exit
  --port PORT        The port to listen on.
  --tcp              Listen to TCP connections.
  --udp              Listen to UDP datagrams.
  --domain DOMAIN    The domain to listen for
  --ttl TTL          TTL value of DNS responses
  --ip IP            IP Adress used to respond
  --rebind REBIND    IP address for rebind
  --counter COUNTER  Number of requests before rebinding
```

Example usage:
```bash
$ python3 dnsrebinder.py --domain ox-rebind.pwnhub.eu. --rebind 127.0.0.1 --ip 8.8.8.8 --counter 2
...
```

This starts a DNS server on port 53 listening on UDP and TCP. The first two(--counter 2) requests will be answered with 8.8.8.8. Every request after that will be answered with the rebind address 127.0.0.1 (--rebind 127.0.0.1).