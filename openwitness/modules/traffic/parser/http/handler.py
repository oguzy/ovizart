#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import dpkt
import gzip
import StringIO
import os
import tempfile
from lxml.html import fromstring
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler
from openwitness.modules.traffic.log.logger import Logger

class Handler(TcpHandler):
    def __init__(self):
        super(Handler, self).__init__()
        self.log = Logger("HTTP Protocol Handler", "DEBUG")
        self.log.message("HTTP protocol handler called")

    def read_http(self, tcp):
        request = self.check_request(tcp)
        if request:
            request_dict = {'method': request.method, 'uri': request.uri, 'headers': request.headers, 'version': request.version}
            return {'request': request_dict}
        else:
            response = self.check_response(tcp)
            if response:
                response_dict = {'headers': response.headers, 'status': response.status, 'body': response.body, 'version': response.version}
                return {'response': response_dict, 'tcp_id': tcp.id}
            return False

    def check_request(self, tcp):
        data = tcp.data
        try:
            return dpkt.http.Request(data)
        except dpkt.UnpackError:
            return False

    def check_response(self, tcp):
        data = tcp.data
        try:
            return dpkt.http.Response(data)
        except dpkt.UnpackError:
            return False

    def get_html(self, response_dict):
        #response will be the dictionary response created after the read_http runs
        html = None
        headers = response_dict['headers']
        body = response_dict['body']
        if 'content-encoding' in headers and headers['content-encoding'] == 'gzip':
            data = StringIO.StringIO(body)
            gzipper = gzip.GzipFile(fileobj = data)
            html = gzipper.read()
        else:
            html = body
        return html

    def save_html(self, html, path):
        html_dir = "/".join([path, "html"])
        if not os.path.exists(path):
            os.mkdir(html_dir)
        html_list = os.listdir(html_dir)
        if not html_list:
            stream_name = "0.html"
        else:
            # the html names will be under html directory with the increasing order as 0.html, 1.html for each flow
            names = map(lambda x: int(x.split(".")[0]), html_list)
            names.sort()
            stream_name = str(names[-1] + 1) + ".html"
        stream_path = "/".join([html_dir, stream_name])
        htmlfile = open(stream_path, 'w')
        htmlfile.write(html)
        htmlfile.close()
        return stream_path

    def get_js(self, path):
        # get the path of html file
        base = os.path.basename(path)
        js_dir = "js"
        js_dir_path = "/".join([base, js_dir])
        if not os.path.exists(js_dir_path):
            os.mkdir(js_dir_path)
        doc = fromstring(path)
        # first the header part
        header = doc.header
        scripts = header.cssselect('script')
        for script in scripts:
            # check whether it defines a src
            items = script.items()
            if items:
                #[('src', 'index_files/adnet_async.js'), ('type', 'text/javascript')]
                # i should do something for these files to, need the requested url
                pass
            else:
                # text between script headers
                txt = script.text()
                data = StringIO.StringIO(txt)
                # create a file and save it
                tmp = tempfile.NamedTemporaryFile(mode="w+", dir=js_dir_path, delete=False)
                tmp.write(data)
                tmp.close()
