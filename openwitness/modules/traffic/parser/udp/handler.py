#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt
import datetime
from openwitness.modules.traffic.log.logger import Logger

class Handler(object):
    def __init__(self):
        super(Handler, self).__init__()
        self.timestamp = None
        self.proto = None
        self.src_ip = None
        self.dst_ip = None
        self.sport = None
        self.dport = None
        self.ident = None
        self.length = None
        self.log = Logger("TCP Protocol Handler", "DEBUG")
        self.log.message("TCP protocol handler called")

    def read_udp(self, ts, buf):
        eth = self.get_eth(buf)
        if not eth:
            return False
        ip = self.get_ip(eth)
        if not ip:
            return False
        self.timestamp = datetime.datetime.fromtimestamp(float(ts))
        udp = self.get_udp(ip)
        return udp

    def get_eth(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            return False
        else:
            return eth

    def get_ip(self, eth):
        ip = eth.data
        self.length = ip.len
        if ip.p != dpkt.ip.IP_PROTO_UDP:
            return False
        else:
            self.proto = ip.p
            self.src_ip = '.'.join(str(ord(c)) for c in ip.src)
            self.dst_ip = '.'.join(str(ord(c)) for c in ip.dst)
            return ip

    def get_udp(self, ip):
        udp = ip.data
        self.ident = ip.id
        self.sport = udp.sport
        self.dport = udp.dport
        return udp

