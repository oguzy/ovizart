#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt

from log.logger import Logger

class Handler:

    def __init__(self, debug_mode="DEBUG"):
        self._logger = Logger(debug_mode)
        self._pcap = None
        self._f = None
        self._filter_type = None
        self._file_pointer = None

    def open_file(self, pcap_file, mode="r"):
        try:
            self._file_pointer = file(pcap_file, mode)
        except:
            self._logger.message("Error at opening pcap file")

    def open_pcap(self, mode="r"):
        if mode == "r":
            self._pcap = dpkt.pcap.Reader(self._file_pointer)
        if mode == "w":
            self._pcap = dpkt.pcap.Writer(self._file_pointer)

    def write_pcap(self, buf, ts):
        self._pcap.writepkt(buf, ts)

    def close_file(self):
        self._f.close()

    def close_pcap(self):
        self._pcap.close()

    def set_filter_type(self, t):
        self._filter_type = t

    def get_filter_type(self):
        return self._filter_type

    def get_pcap(self):
        return self._pcap

    def get_eth(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            return eth
        else:
            return False

    def get_ip(self, eth):
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            return ip
        else:
            return False

    def get_tcp(self, ip):
        tcp = ip.data
        return tcp




