#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
sys.path.append("../")

import dpkt
from ovizart.modules.traffic.log.logger import Logger

class Handler:

    def __init__(self, debug_mode="DEBUG"):
        self._logger = Logger(log_name="Pcap Handler", log_mode=debug_mode)
        self._logger.message("Pcap Handler initialized")
        self._pcap = None
        self._filter_type = None
        self._file_pointer = None

    def open_file(self, pcap_file, mode="rb"):
        try:
            self._file_pointer = file(pcap_file, mode)
            self._logger.set_log_level("DEBUG")
            self._logger.message(("%s is opened at %s mode") % (pcap_file, mode))
        except:
            self._logger.set_log_level("ERROR")
            self._logger.message("Error at opening pcap file")

    def open_pcap(self, mode="r"):
        if mode == "r":
            self._pcap = dpkt.pcap.Reader(self._file_pointer)
            self._logger.set_log_level("DEBUG")
            self._logger.message("pcap reader is created")
        if mode == "w":
            self._pcap = dpkt.pcap.Writer(self._file_pointer)

    def write_pcap(self, buf, ts):
        self._pcap.writepkt(buf, ts)

    def close_file(self):
        self._file_pointer.close()

    def set_filter_type(self, t):
        self._filter_type = t
        self._logger.set_log_level("DEBUG")
        self._logger.message(("Filter type is set %s") % (t))

    def get_filter_type(self):
        return self._filter_type

    def get_pcap(self):
        return self._pcap

    def get_eth(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            return eth
        else:
            self._logger.set_log_level("ERROR")
            self._logger.message("No Eth is returned")
            return False

    def get_ip(self, eth):
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            return ip
        else:
            self._logger.set_log_level("ERROR")
            self._logger.message("No IP is returned")
            return False

    def get_tcp(self, ip):
        tcp = ip.data
        #self._logger.message(("TCP is returned %s") % (tcp))
        return tcp

    def get_udp(self, ip):
        udp = ip.data
        return udp

    def get_reader(self):
        return self._pcap


