#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt

class Handler:
    def __init__(self, file_name):
        f = file(file_name, "rb")
        self.pcap = dpkt.pcap.Reader(f)
        self.timestamp = None
        self.proto = None
        self.src_ip = None
        self.dst_ip = None
        self.sport = None
        self.dport = None
        self.r = []

    def read(self):
        for ts, buf in self.pcap:
            eth = self.get_eth(buf)
            if not eth: continue
            ip = self.get_ip(self, eth)
            if not ip: continue
            self.timestamp = ts
            tcp = self.get_tcp(ip)
            request = self.check_request(tcp)
            if request:
                request_dict = {'method': request.method, 'uri': request.uri, 'headers': request.headers, 'version': request.version}
                self.r.append(("request", request_dict))
            else:
                response = self.check_response(tcp)
            if response:
                response_dict = {'headers': response.headers, 'status': response.status, 'body': response.body, 'version': response.version}
                self.r.append(("response", response_dict))
        return self.r


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

    def check_request(self, tcp):
        data = tcp.data
        try:
            return dpkt.http.Request(data)
        except dpkt.UnpackError:
            return False

    def check_response(self, tcp):
        data = tcp.data
        try:
            return dpkt.http.Responce(data)
        except dpkt.UnpackError:
            return False

