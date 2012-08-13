#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from ovizart.modules.traffic.pcap.handler import Handler as PcapHandler
from ovizart.modules.traffic.parser.udp.handler import Handler as UDPHandler
from ovizart.pcap.models import DNSRequest, DNSResponse, FlowDetails
from ovizart.modules.traffic.log.logger import Logger
from socket import inet_ntoa, inet_ntop, AF_INET6

import dpkt

REQUEST_FLAGS = {dpkt.dns.DNS_A:'A', dpkt.dns.DNS_NS:'NS', dpkt.dns.DNS_CNAME:'CNAME',
                 dpkt.dns.DNS_SOA:'SOA', dpkt.dns.DNS_PTR:'PTR', dpkt.dns.DNS_HINFO:'HINFO',
                 dpkt.dns.DNS_MX:'MX', dpkt.dns.DNS_TXT:'TXT',
                 dpkt.dns.DNS_AAAA:'AAAA', dpkt.dns.DNS_SRV:'SRV'}

RESPONSE_FLAGS = {dpkt.dns.DNS_A:'A', dpkt.dns.DNS_NS:'NS', dpkt.dns.DNS_CNAME:'CNAME',
                 dpkt.dns.DNS_SOA:'SOA', dpkt.dns.DNS_PTR:'PTR', dpkt.dns.DNS_HINFO:'HINFO',
                 dpkt.dns.DNS_MX:'MX', dpkt.dns.DNS_TXT:'TXT',
                 dpkt.dns.DNS_AAAA:'AAAA', dpkt.dns.DNS_SRV:'SRV'}


class Handler():
    def __init__(self):
        self.log = Logger("DNS Protocol Handler", "DEBUG")
        self.log.message("DNS protocol handler called")
        self.dns_li = []
        self.flow_li = []

    def get_flow_ips(self, **args):
        path = args['path']
        file_name = args['file_name']
        # TODO: this handler should read the conn.log and get the flows there
        p_read_handler = PcapHandler()
        file_path = "/".join([path, file_name])
        p_read_handler.open_file(file_path)
        p_read_handler.open_pcap()
        udp_handler = UDPHandler()
        for ts, buf in p_read_handler.get_reader():
            udp = udp_handler.read_udp(ts, buf)
            if udp:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    self.flow_li.append([udp_handler.src_ip, udp_handler.sport, udp_handler.dst_ip, udp_handler.dport, udp_handler.timestamp])
                except IndexError:
                    continue  #dpkt is not properly handling
                self.dns_li.append(dns)
        return self.flow_li

    def save_request_response(self, **args):
        index = 0
        for msg in self.dns_li:
            if msg.rcode == dpkt.dns.DNS_RCODE_NOERR:
                try:
                    msg.qd[0].type
                except:
                    continue
                if msg.qd[0].type in REQUEST_FLAGS.keys():
                    detail = self.flow_li[index]
                    flow_detail = FlowDetails.objects.get(src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="dns", timestamp = detail[4])
                    try:
                        dns_request = DNSRequest(type=msg.qd[0].type, human_readable_type=REQUEST_FLAGS[msg.qd[0].type], value=msg.qd[0].name, flow_details=flow_detail)
                        dns_request.save()
                    except Exception, ex:
                        print ex
                for an in msg.an:
                    if an.type in RESPONSE_FLAGS.keys():
                        flow_detail = self.flow_li[index]
                        type = an.type
                        human_readable_type = REQUEST_FLAGS[type]
                        value = None
                        if type == dpkt.dns.DNS_SOA:
                            value = [an.mname, an.rname, str(an.serial),str(an.refresh), str(an.retry), str(an.expire), str(an.minimum) ]
                        if type == dpkt.dns.DNS_A:
                            value = [inet_ntoa(an.ip)]
                        if type == dpkt.dns.DNS_PTR:
                            value = [an.ptrname]
                        if type == dpkt.dns.DNS_NS:
                            value = [an.nsname]
                        if type == dpkt.dns.DNS_CNAME:
                            value = [an.cname]
                        if type == dpkt.dns.DNS_HINFO:
                            value = [" ".join(an.text)]
                        if type == dpkt.dns.DNS_MX:
                            value = [an.mxname]
                        if type == dpkt.dns.DNS_TXT:
                            value = " ".join(an.text)
                        if type == dpkt.dns.DNS_AAAA:
                            value = inet_ntop(AF_INET6,an.ip6)
                        detail = self.flow_li[index]
                        flow_detail = FlowDetails.objects.get(src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="dns", timestamp = detail[4])
                        dns_response = DNSResponse(type=type, human_readable_type=RESPONSE_FLAGS[type], value=value, flow_details = flow_detail)
                        dns_response.save()
                index += 1
        return True