#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt
import datetime

class Handler(object):
    def __init__(self):
        super(Handler, self).__init__()
        self.timestamp = None
        self.proto = None
        self.src_ip = None
        self.dst_ip = None
        self.sport = None
        self.dport = None

    def read_tcp(self, ts, buf):
        eth = self.get_eth(buf)
        if not eth:
            return False
        ip = self.get_ip(eth)
        if not ip:
            return False
        self.timestamp = datetime.datetime.fromtimestamp(float(ts))
        tcp = self.get_tcp(ip)
        return tcp

    def get_eth(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            return False
        else:
            return eth

    def get_ip(self, eth):
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            return False
        else:
            self.proto = ip.p
            self.src_ip = '.'.join(str(ord(c)) for c in ip.src)
            self.dst_ip = '.'.join(str(ord(c)) for c in ip.dst)
            return ip

    def get_tcp(self, ip):
        tcp = ip.data
        self.sport = tcp.sport
        self.dport = tcp.dport
        return tcp

    def close_file(self):
        self.f.close()
