#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
sys.path.append("../")

from pcap.handler import Handler
from log.logger import Logger

class Handler:

    def __init__(self, handler, debug_mode="DEBUG"):
        self.pcap = handler.get_pcap()
        self.pcap_handler = handler
        self._logger = Logger(log_name="Flow Handler", log_mode=debug_mode)
        self._logger.message("Flow Handler initialized")

    def get_tcp_flows(self, filter_type="TCP"):
        flow = dict()
        flow_id = 0
        flow_num = 0
        direction = dict() # 1 is one, 2 is bidirectional, keep the flow numbers as indexes
        index = dict()
        self.pcap_handler.set_filter_type(filter_type)
        for ts, buf in self.pcap:
            eth = self.pcap_handler.get_eth(buf)
            if eth:
                ip = self.pcap_handler.get_ip(eth)
            else:
                continue
            #src_ip = self.ip.src
            #dst_ip = self.ip.dst
            # for human readable ip
            # from socket import inet_ntoa
            # inet_ntoa(dst_ip)
            if self.pcap_handler.get_filter_type() == "TCP":
                if not ip:
                    continue
                tcp = self.pcap_handler.get_tcp(ip)
                forward_index = (ip.src, tcp.sport, ip.dst, tcp.dport)
                backward_index = (ip.dst, tcp.dport, ip.src, tcp.sport)
                if index.has_key(forward_index):
                    flow_num = index[forward_index]
                elif index.has_key(backward_index):
                    flow_num = index[backward_index]
                    direction[flow_num] = 2
                else:
                    index[forward_index] = flow_id
                    flow_num = flow_id
                    direction[flow_num] = 1

                if flow.has_key(flow_num):
                    flow[flow_num].append((buf,ts))
                else:
                    flow[flow_num] = [(buf, ts)]
            flow_id += 1
        return flow, direction

    def save_flow(self, flow, pcap_handler, save_path=""):

        for key, values in flow.iteritems():
            file_name = ".".join([str(key), "pcap"])
            full_file_path = "/".join([save_path, file_name])
            pcap_handler.open_file(full_file_path, "w")
            pcap_handler.open_pcap("w")
            for value in values:
                pcap_handler.write_pcap(value[0], value[1])
            pcap_handler.close_file()
            pcap_handler.close_pcap()


