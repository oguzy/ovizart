#!/usr/bin/env python
#-*- coding: UTF-8 -*-


from pcap import handler as pcap_handler
from flow import handler as flow_handler

p_read_handler = pcap_handler.Handler()
p_read_handler.open_file("../pcaps/http.pcap")
p_read_handler.open_pcap()

f_handler = flow_handler.Handler(p_read_handler)
flow, direction = f_handler.get_tcp_flows()

p_write_handler = pcap_handler.Handler()
f_handler.save_flow(flow, p_write_handler)
