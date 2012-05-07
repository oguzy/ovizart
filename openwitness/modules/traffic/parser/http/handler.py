#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler

class Handler(TcpHandler):
    def __init__(self, file_name):
        super(Handler, self).__init__()
        self.r = []

    def read_http(self, tcp):
        request = self.check_request(tcp)
        if request:
            request_dict = {'method': request.method, 'uri': request.uri, 'headers': request.headers, 'version': request.version}
            self.r.append(("request", request_dict))
        else:
            response = self.check_response(tcp)
        if response:
            response_dict = {'headers': response.headers, 'status': response.status, 'body': response.body, 'version': response.version}
            self.r.append(("response", response_dict))

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

