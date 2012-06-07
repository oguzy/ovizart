# Create your views here.

import hashlib
import urllib2
import simplejson
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap.handler import Handler as PcapHandler
from openwitness.modules.traffic.flow.handler import Handler as FlowHandler
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler
from openwitness.modules.traffic.parser.udp.handler import Handler as UDPHandler
from openwitness.modules.md5.handler import Handler as HashHandler

from openwitness.pcap.models import Flow, Pcap, PacketDetails, FlowDetails

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
            hash_value = hash_handler.get_hash()
            flow_file, created = Flow.objects.get_or_create(hash_value=hash_value,file_name=pcap_name, path=upload_path)
            request.session['uploaded_hash'] = hash_value
            request.session['uploaded_file_name'] = pcap_name
            # send the file to the defined protocol handler so that it can detect
            protocol_handler = settings.PROTOCOL_HANDLER
            package = "openwitness.modules.traffic.detector"
            module_name = ".".join([package, protocol_handler])
            # from openwitness.modules.traffic.detector.x import handler as imported_module
            traffic_detector_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
            traffic_detector_handler = traffic_detector_module.Handler()
            traffic_detector_handler.create_reassemble_information(file_handler.file_path, upload_path)
            output = traffic_detector_handler.detect_proto(file_handler.file_path, upload_path)
            if "tcp" in output:
                log.message("protocol detected: %s" % "TCP")
                # run tcp flow extractor
                p_read_handler = PcapHandler()
                p_read_handler.open_file(file_handler.file_path)
                p_read_handler.open_pcap()

                f_handler = FlowHandler(p_read_handler)
                flow, direction = f_handler.get_tcp_flows()

                p_write_handler = PcapHandler()
                files = f_handler.save_flow(flow, p_write_handler, save_path=upload_path)

                # save the flow pcap names to the mongo db
                pcap_list = map(lambda x: Pcap.objects.create(hash_value=hashlib.md5("/".join([upload_path, x])).hexdigest(), file_name=x, path=upload_path), files.values()[0])
                flow_file.pcaps = pcap_list
                flow_file.save()

                p_read_handler.close_file()
                p_write_handler.close_file()
                # now i should hook a protocol detector
                # before that i should detect the application level protocol
                for f in files.values()[0]:
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
                        packet = PacketDetails.objects.create(ident=tcp_handler.ident, timestamp=tcp_handler.timestamp, protocol=tcp_handler.proto, src_ip=tcp_handler.src_ip, dst_ip=tcp_handler.dst_ip, sport=tcp_handler.sport, dport=tcp_handler.dport)
                        packets.append(packet)
                    hash_handler.set_file("/".join([upload_path, f]))
                    # get the pcap object
                    p = Pcap.objects.get(hash_value=hash_handler.get_hash())
                    log.message("pcap for packet update detected: %s" % p)
                    # update its packets
                    p.packets = list(packets) # converting a queryset to list
                    p.save()
                    p_read_handler.close_file()

            if "udp" in output:
                log.message("protocol detected: %s" % "UDP")
                p_read_handler = PcapHandler()
                file_path = "/".join([upload_path, pcap_name])
                p_read_handler.open_file(file_path)
                p_read_handler.open_pcap()
                udp_handler = UDPHandler()
                pcap = Pcap.objects.create(hash_value=hashlib.md5("/".join([upload_path, pcap_name])).hexdigest(), file_name=pcap_name, path=upload_path)
                pcap_list = list([pcap])
                flow_file.pcaps = pcap_list
                flow_file.save()

                packets  = []
                for ts, buf in p_read_handler.get_reader():
                    udp = udp_handler.read_udp(ts, buf)
                    if udp:
                        packet = PacketDetails.objects.create(ident=udp_handler.ident, timestamp=udp_handler.timestamp, protocol=udp_handler.proto, src_ip=udp_handler.src_ip, dst_ip=udp_handler.dst_ip, sport=udp_handler.sport, dport=udp_handler.dport)
                        packets.append(packet)
                        hash_handler.set_file("/".join([upload_path, pcap_name]))
                        # get the pcap object
                p = Pcap.objects.get(hash_value=hash_handler.get_hash())
                # update its packets
                p.packets = list(packets) # converting a queryset to list
                p.save()
                p_read_handler.close_file()


            # starting the bro related issues for the reassembled data
            output = traffic_detector_handler.detect_appproto(file_handler.file_path, upload_path)
            log.message("protocol detected: %s" % output)
            if "http" in output:
                log.message("protocol detected: %s" % "HTTP")
                # save the reassembled http session IPs to FlowDetails

                # this part is checking the http handler module name and importing the handler
                http_protocol_handler = settings.HTTP_HANDLER
                package = "openwitness.modules.traffic.parser.tcp"
                module_name = ".".join([package, http_protocol_handler])
                # from openwitness.modules.traffic.parser.tcp.x import handler as imported_module
                http_handler_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                http_handler = http_handler_module.Handler()
                # define a get_flow_ips function for the custom handler if required
                # TODO: save the timestamps of the flows
                flow_ips = http_handler.get_flow_ips(path=upload_path)
                flow_detail_li = []
                for detail in flow_ips:
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], session_key=request.session.session_key, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="http", timestamp = detail[4])
                    flow_detail_li.append(flow_detail)
                flow_file.details = flow_detail_li
                flow_file.save()
                # then call functions that will save request and responses that will parse dat files, save the headers and files
                http_handler.save_request(path=upload_path, hash_value=request.session['uploaded_hash'])
                http_handler.save_response(path=upload_path, hash_value=request.session['uploaded_hash'])
                # should save the file names to db also

            # dns realted issues starts here
            if "dns" in output:
                log.message("protocol detected: %s" % "DNS")
                dns_protocol_handler = settings.DNS_HANDLER
                package = "openwitness.modules.traffic.parser.udp"
                module_name = ".".join([package, dns_protocol_handler])
                # from openwitness.modules.traffic.parser.udp.x import handler as imported_module
                dns_handler_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                dns_handler = dns_handler_module.Handler()
                # define a get_flow_ips function for the custom handler if required
                flow_ips = dns_handler.get_flow_ips(path=upload_path, file_name=request.session['uploaded_file_name'])
                flow_detail_li = []
                for detail in flow_ips:
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], session_key=request.session.session_key, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="dns", timestamp = detail[4])
                    flow_detail_li.append(flow_detail)
                flow_file.details = flow_detail_li
                flow_file.save()

                dns_handler.save_request_response()

            if "smtp" in output:
                log.message("protocol detected: %s" % "SMTP")
                smtp_protocol_handler = settings.SMTP_HANDLER
                package = "openwitness.modules.traffic.parser.tcp"
                module_name = ".".join([package, smtp_protocol_handler])
                # from openwitness.modules.traffic.parser.tcp.x import handler as imported_module
                smtp_handler_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                smtp_handler = smtp_handler_module.Handler()
                # define a get_flow_ips function for the custom handler if required
                smtp_handler.set_flow(flow_file) # i need this, to get the timestamp from a packet belongs to the flow
                flow_ips = smtp_handler.get_flow_ips(path=upload_path, file_name=request.session['uploaded_file_name'])
                flow_detail_li = []
                for detail in flow_ips:
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], session_key=request.session.session_key, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="smtp", timestamp = detail[4])
                    flow_detail_li.append(flow_detail)
                flow_file.details = flow_detail_li
                flow_file.save()

                smtp_handler.save_request_response(upload_path=upload_path)

    else:
        form = UploadPcapForm()
        context['form'] = form

    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))

def summary(request):
    #session_key = request.session.session_key
    url = "".join([settings.BASE_URL, "/api/protocols/?format=json&session_key=", "3003981449cc81a75883443612258a1a"])
    req = urllib2.Request(url, None)
    opener = urllib2.build_opener()
    f = None
    try:
        f = opener.open(req)
        json_response = simplejson.load(f)
        print json_response
    except Exception, ex:
        print ex






