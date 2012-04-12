#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt
import sys
import os
import StringIO

f = file("pcaps/http.pcap")
pcap = dpkt.pcap.Reader(f)

counter = 0

for ts, buf in pcap:
    counter = counter + 1
    print "packet:", counter
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    tcp_data = tcp.data

    if tcp.dport == 80 and len(tcp.data)>0:
        request = dpkt.http.Request(tcp_data)
        #print "\t http request gathered\n"
        #print "\t request:", request.body
    else:
        try:
            if tcp_data[:4] == "HTTP":
                try:
                    http = dpkt.http.Response(tcp_data)
                    #do something with the response data
                    # body part is empty for the 73. package, although the header says it is an image file
                    print "\t http response gathered\n"
                except Exception, ex:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

                    print "\t HTTP response error:", (exc_type, fname, exc_tb.tb_lineno)

        except Exception, ex:
            print ex

f.close()
