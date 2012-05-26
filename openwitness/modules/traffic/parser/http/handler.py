#!/usr/bin/env python
#-*- coding: UTF-8 -*-


import os
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler
from openwitness.modules.traffic.log.logger import Logger
from openwitness.pcap.models import Flow, HttpDetails
from openwitness.modules.file.handler import Handler as FileHandler

from hachoir_core.cmd_line import unicodeFilename
from hachoir_core.stream import FileInputStream
from hachoir_subfile.search import SearchSubfile

class Handler(TcpHandler):
    def __init__(self):
        super(Handler, self).__init__()
        self.log = Logger("HTTP Protocol Handler", "DEBUG")
        self.log.message("HTTP protocol handler called")

#    def read_http(self, tcp):
#        request = self.check_request(tcp)
#        if request:
#            request_dict = {'method': request.method, 'uri': request.uri, 'headers': request.headers, 'version': request.version}
#            return {'request': request_dict}
#        else:
#            response = self.check_response(tcp)
#            if response:
#                response_dict = {'headers': response.headers, 'status': response.status, 'body': response.body, 'version': response.version}
#                return {'response': response_dict, 'tcp_id': tcp.id}
#            return False
#
#    def check_request(self, tcp):
#        data = tcp.data
#        try:
#            return dpkt.http.Request(data)
#        except dpkt.UnpackError:
#            return False

#    def check_response(self, tcp):
#        data = tcp.data
#        try:
#            return dpkt.http.Response(data)
#        except dpkt.UnpackError:
#            return False
#
#    def get_html(self, response_dict):
#        #response will be the dictionary response created after the read_http runs
#        html = None
#        headers = response_dict['headers']
#        body = response_dict['body']
#        if 'content-encoding' in headers and headers['content-encoding'] == 'gzip':
#            data = StringIO.StringIO(body)
#            gzipper = gzip.GzipFile(fileobj = data)
#            html = gzipper.read()
#        else:
#            html = body
#        return html
#
#    def save_html(self, html, path):
#        html_dir = "/".join([path, "html"])
#        if not os.path.exists(path):
#            os.mkdir(html_dir)
#        html_list = os.listdir(html_dir)
#        if not html_list:
#            stream_name = "0.html"
#        else:
#            # the html names will be under html directory with the increasing order as 0.html, 1.html for each flow
#            names = map(lambda x: int(x.split(".")[0]), html_list)
#            names.sort()
#            stream_name = str(names[-1] + 1) + ".html"
#        stream_path = "/".join([html_dir, stream_name])
#        htmlfile = open(stream_path, 'w')
#        htmlfile.write(html)
#        htmlfile.close()
#        return stream_path
#
#    def get_js(self, path, tcp):
#        # get the path of html file
#        base = os.path.dirname(path)
#        js_dir = "js"
#        js_dir_path = "/".join([base, js_dir])
#        if not os.path.exists(js_dir_path):
#            os.mkdir(js_dir_path)
#        doc = fromstring(path)
#        # first the header part
#        header = doc.header
#        scripts = header.cssselect('script')
#        for script in scripts:
#            # check whether it defines a src
#            items = script.items()
#            if items:
#                #[('src', 'index_files/adnet_async.js'), ('type', 'text/javascript')]
#                # i should do something for these files to, need the requested url
#                js_status = False
#                src_status = False
#                src = None
#                for item in items:
#                    if 'type' in item and 'text/javascript' in item:
#                        js_status = False
#                    if 'src' in item:
#                        src_status = True
#                        src = item[1]
#
#                if js_status and src_status:
#                    file_name = src.split("/")[-1]
#                    url = "/".join([tcp.dst_ip, src])
#                    u = urllib2.urlopen(url)
#                    path = "/".join([js_dir_path, file_name])
#                    localFile = open(path, 'w')
#                    localFile.write(u.read())
#                    localFile.close()
#
#            else:
#                # text between script headers
#                txt = script.text()
#                data = StringIO.StringIO(txt)
#                # create a file and save it
#                tmp = tempfile.NamedTemporaryFile(mode="w+", dir=js_dir_path, delete=False)
#                tmp.write(data)
#                tmp.close()
#
#    def read_http_log(self, path):
#        # first check whether there is an http.log created
#        result = []
#        full_path = "/".join([path, "http.log"])
#        if os.path.exists(full_path):
#            f = open(full_path, "r")
#            for line in f.readlines():
#                if line.startswith("#"):
#                    continue
#                else:
#                    data = line.split()
#                    # src ip, sport, dst ip, dport
#                    result.append(data[2:6])
#        else:
#            return False
#
#        return result

    def read_dat_files(self, path):
        result = []
        files = os.listdir(path)
        for f in files:
            f_path = "/".join([path, f])
            if os.path.isdir(f_path):
                continue
            #contents_192.168.1.5:42825-62.212.84.227:80_orig.dat
            name = f.split("_")
            extension = name[-1].split(".")[-1]
            if extension == "dat":
                communication = name[1].split("-")
                source = communication[0].split(":")
                destination = communication[1].split(":")
                source.extend(destination)
                result.append(source)
            else:
                continue

        return result


    def get_flow_ips(self,path):
        return self.read_dat_files(path)

    def save_request(self, path, hash_value):
        # the the ip from database

        try:
            flow = Flow.objects.get(hash_value=hash_value)
            flow_details = flow.details
            for detail in flow_details:
                # create the orig file ex: contents_192.168.1.5:42825-62.212.84.227:80_resp.dat
                source_str = ":".join([detail.src_ip, detail.sport])
                destination_str = ":".join([detail.dst_ip, detail.dport])
                flow_str = "-".join([source_str, destination_str])
                orig_file = "_".join(["contents", flow_str,"orig.dat"])
                file_path = "/".join([path, orig_file])

                strings = ["GET", "PUT", "POST"]
                file_handler = FileHandler()
                requests = []
                for item in file_handler.search(file_path, strings):
                    requests.append(item[0])

                # i am making a hacky thing here, finding empty lines, each request is separeted with an empty line
                empty_lines = []
                strings = ["\r\n\r\n"]
                for item in file_handler.search(file_path, strings):
                    empty_lines.append(item[0])

                for x in range(len(requests)):
                    # here i have the request header
                    data = file_handler.data
                    request = data[requests[x]:empty_lines[x]]
                    request_li = request.split("\n")

                    for entry in request_li:
                        # the first line is method and uri with version information
                        info = entry.split(":")
                        if len(info) == 1:
                            info = info.split()
                            method = info[0]
                            uri = info[1]
                            version = info[2].split("/")[1]

                            http_details = HttpDetails.objects.get_or_create(http_type="request", method=method, uri=uri, headers=request_li, version=version, flow=flow)

                            return True


        except:
            return False

    def save_response_headers(self, path, hash_value):
        try:
            flow = Flow.objects.get(hash_value=hash_value)
            flow_details = flow.details
            for detail in flow_details:
                # create the orig file ex: contents_192.168.1.5:42825-62.212.84.227:80_resp.dat
                source_str = ":".join([detail.src_ip, detail.sport])
                destination_str = ":".join([detail.dst_ip, detail.dport])
                flow_str = "-".join([source_str, destination_str])
                resp_file = "_".join(["contents", flow_str,"resp.dat"])
                file_path = "/".join([path, resp_file])

                strings = ["HTTP/1.1"]
                file_handler = FileHandler()
                responses = []
                for item in file_handler.search(file_path, strings):
                    responses.append(item[0])

                empty_lines = []
                strings = ["\r\n\r\n"]
                for item in file_handler.search(file_path, strings):
                    empty_lines.append(item[0])

                for x in range(len(responses)):
                    # here i have the request header
                    data = file_handler.data
                    response = data[responses[x]:empty_lines[x]]
                    response_li = response.split("\n")

                    header = info = version = status = content_type = None

                    for entry in response_li:
                        # the first line is method and uri with version information
                        info = entry.split(":")
                        if len(info) == 1:
                            info = info.split()
                            version = info[0].split("/")[1]
                            header = response_li
                            status = info[1]
                        else:
                            if "Content-Type" in info:
                                content_type = info[1]


                        http_details = HttpDetails.objects.get_or_create(http_type="response", version=version, header=header, status=status, content_type=content_type, flow=flow)

                        return True

        except:
            return False


    def save_response_files(self, path, hash_value):
        try:
            flow = Flow.objects.get(hash_value=hash_value)
            flow_details = flow.details
            for detail in flow_details:
                # create the orig file ex: contents_192.168.1.5:42825-62.212.84.227:80_resp.dat
                source_str = ":".join([detail.src_ip, detail.sport])
                destination_str = ":".join([detail.dst_ip, detail.dport])
                flow_str = "-".join([source_str, destination_str])
                resp_file = "_".join(["contents", flow_str,"resp.dat"])
                file_path = "/".join([path, resp_file])

                stream = FileInputStream(unicodeFilename(file_path), real_filename=file_path)
                subfile = SearchSubfile(stream, 0, None)
                subfile.loadParsers()
                output = flow_str
                if not os.path.exists(output):
                    os.mkdir(output)
                subfile.setOutput(output)
                ok = subfile.main()

                # save the files info at the db also

            return True

        except:
            return False

