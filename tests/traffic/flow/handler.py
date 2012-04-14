#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from pcap.handler import Handler

class Flow:

    def __init__(self, handler):
        self.pcap = handler.get_pcap()

    def get_tcp_flows(self):
        flow = dict()
        flow_id = 0
        packets = []
        tpl_index = dict()
        for ts, buf in self.pcap:
            eth = handler.get_eth(buf)
            if eth:
                ip = handler.get_ip(eth)
            #src_ip = self.ip.src
            #dst_ip = self.ip.dst
            # for human readable ip
            # from socket import inet_ntoa
            # inet_ntoa(dst_ip)
            if self.get_filter_type() == "TCP":
                if not ip:
                    continue
                tcp = handler.get_tcp(self.ip)
                tpl_forward = (ip.src, tcp.sport, ip.dst, tcp.dport)
                tpl_backward = (ip.dst, tcp.dport, ip.src, tcp.sport)
                if tpl_index.has_key(flow_id):
                    flow[id] = packets.append((buf, ts))
                else:
                    tpl_index[id] = [tpl_forward, tpl_backward]
        return flow

    def save_flow(self, flow):

        for key, values in flow.iteritems():
            file_name = ".".join([str(key), "pcap"])
            handler.open_file(file_name, "w")
            handle.open_pcap("w")
            handler.write_pcap(values[0], values[1])
        handler.close_file()
        handler.close_pcap()


