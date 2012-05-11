# Create your views here.

import hashlib
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap.handler import Handler as PcapHandler
from openwitness.modules.traffic.flow.handler import Handler as FlowHandler
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler
from openwitness.modules.traffic.parser.http.handler import Handler as HttpHandler
from openwitness.modules.md5.handler import Handler as HashHandler

from openwitness.pcap.models import Flow, Pcap, PacketDetails, HttpDetails

from openwitness.modules.traffic.log.logger import Logger

def upload(request):
    log = Logger("Upload form", "DEBUG")
    context = {
        'page_title': 'Upload your pcap file here',
        'upload_status': False
    }
    if request.method == "POST":
        form = UploadPcapForm(request.POST, request.FILES)
        if form.is_valid():
            context['form'] = form
            file_handler = FileHandler()
            file_handler.create_dir()
            mem_file = request.FILES['pcap_file']
            log.message("file: %s" % mem_file.name)
            file_handler.save_file(mem_file)
            context['upload_status'] = True

            #save the file name to the db
            pcap_name = mem_file.name
            upload_path = file_handler.upload_dir
            # evey pcap file is saved as a flow container, there may or may not be flows, the pcaps colon will give the flow pcaps
            hash_handler = HashHandler()
            hash_handler.set_file("/".join([pcap_name, upload_path]))
            flow_file, created = Flow.objects.get_or_create(hash_value=hash_handler.get_hash(),file_name=mem_file.name, path=upload_path)
            # send the file to the defined protocol handler so that it can detect
            protocol_handler = settings.PROTOCOL_HANDLER
            package = "openwitness.modules.traffic.detector"
            module_name = ".".join([package, protocol_handler])
            # from openwitness.modules.traffic.detector.x import handler as imported_module
            traffic_detector_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
            traffic_detector_handler = traffic_detector_module.Handler()
            output = traffic_detector_handler.detect_proto(file_handler.file_path, upload_path)
            log.message("protocol detected: %s" % output)
            if "tcp" in output:
                # run tcp flow extractor
                p_read_handler = PcapHandler()
                p_read_handler.open_file(file_handler.file_path)
                p_read_handler.open_pcap()

                f_handler = FlowHandler(p_read_handler)
                flow, direction = f_handler.get_tcp_flows()

                p_write_handler = PcapHandler()
                files = f_handler.save_flow(flow, p_write_handler, save_path=upload_path)

                # save the flow pcap names to the mongo db
                pcap_list = map(lambda x: Pcap.objects.create(hash_value=hashlib.md5("/".join([x, upload_path])).hexdigest(), file_name=x, path=upload_path), files.values())
                flow_file.pcaps = pcap_list
                flow_file.save()

                p_read_handler.close_file()
                p_write_handler.close_file()
                # now i should hook a protocol detector
                # before that i should detect the application level protocol
                for f in files.values():
                    packets  = []
                    # better to save tcp level information to db here
                    full_path = "/".join([upload_path, f])
                    p_read_handler.open_file(full_path)
                    p_read_handler.open_pcap()
                    pcap = p_read_handler.get_pcap()
                    # the list that will keep the tcp part of the packet
                    tcp_list = []
                    for ts, buf in pcap:
                        tcp_handler = TcpHandler()
                        tcp = tcp_handler.read_tcp(ts, buf)
                        # this list will be used at the layers above tcp
                        if tcp:
                            tcp_list.append((tcp, tcp_handler.ident))
                        else: continue
                        PacketDetails.objects.create(ident=tcp_handler.ident, timestamp=tcp_handler.timestamp, protocol=tcp_handler.proto, src_ip=tcp_handler.src_ip, dst_ip=tcp_handler.dst_ip, sport=tcp_handler.sport, dport=tcp_handler.dport)
                    packets = PacketDetails.objects.all()
                    hash_handler.set_file("/".join([f, upload_path]))
                    # get the pcap object
                    p = Pcap.objects.get(hash_value=hash_handler.get_hash())
                    log.message("pcap for packet update detected: %s" % p)
                    # update its packets
                    p.packets = list(packets) # converting a queryset to list
                    p.save()

                    output = traffic_detector_handler.detect_appproto(f, upload_path)
                    log.message("protocol detected: %s" % output)
                    if output.strip().lower() == "http":
                        # by looking at the output http hook the parser related with it
                        http_handler = HttpHandler()

                        if tcp_list:
                            for tcp in tcp_list:
                                # get the http information to a list
                                http_info = http_handler.read_http(tcp[0])
                        # save the result of the http infor to db
                                http = None
                                if http_info and http_info.has_key('request'):
                                    # {'method': request.method, 'uri': request.uri, 'headers': request.headers, 'version': request.version}
                                    info = http_info['request']
                                    http = HttpDetails.objects.create(http_type="request", method=info['method'], uri=info['uri'], headers=info['headers'], version=info['version'])
                                if http_info and http_info.has_key('response'):
                                    #{'headers': response.headers, 'status': response.status, 'body': response.body, 'version': response.version}
                                    info = http_info['response']
                                    http = HttpDetails.objects.create(http_type="response", headers=info['headers'], status=info['status'], body=info['body'], version=info['version'])

                                    # save the returned html and js files to the disk
                                    html = http_handler.get_html(info['headers'])
                                    stream_path = http_handler.save_html(html, upload_path)
                                    http_handler.get_js(stream_path)

                                # save the packet http information
                                tcp_packet = filter(lambda x: x.ident == tcp[1], p.packets)[0]
                                if not http:
                                    tcp_packet.http = http
                                    tcp_packet.save()

                    p_read_handler.close_file()

    else:
        form = UploadPcapForm()
        context['form'] = form

    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))
