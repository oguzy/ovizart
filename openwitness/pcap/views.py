# Create your views here.

import hashlib
import urllib2
import tempfile
import os
import datetime
import cgi
from django.http import Http404
from django.utils import simplejson as json
from django.shortcuts import render_to_response
from django.template.context import RequestContext
from django.conf import settings
from openwitness.pcap.forms import UploadPcapForm
from openwitness.modules.file.handler import Handler as FileHandler
from openwitness.modules.traffic.pcap.handler import Handler as PcapHandler
from openwitness.modules.traffic.flow.handler import Handler as FlowHandler
from openwitness.modules.traffic.parser.tcp.handler import Handler as TcpHandler
from openwitness.modules.traffic.parser.udp.handler import Handler as UDPHandler
from openwitness.pcap.models import UserJSonFile
from openwitness.modules.md5.handler import Handler as HashHandler

from openwitness.pcap.models import Flow, Pcap, PacketDetails, FlowDetails
from openwitness.modules.utils.handler import translate_time

from openwitness.modules.traffic.log.logger import Logger
from django.contrib.auth.decorators import login_required

# for development purposes, when the login screen is defined this should be removed
from openwitness.api.constants import  ICONS

@login_required()
def upload(request):
    log = Logger("Upload form", "DEBUG")
    context = {
        'page_title': 'Upload your pcap file here',
        'upload_status': False
    }
    if request.method == "POST":
        form = UploadPcapForm(request.POST, request.FILES)
        if form.is_valid():
            user_id = request.user.id
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
            flow_file, created = Flow.objects.get_or_create(user_id=user_id, hash_value=hash_value,file_name=pcap_name, path=upload_path)
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
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], user_id=user_id, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="http", timestamp = detail[4])
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
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], user_id=user_id, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="dns", timestamp = detail[4])
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
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], user_id=user_id, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="smtp", timestamp = detail[4])
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
    # to get this work, runserver should be run as bin/django runserver 127.0.0.0:8001 and another instance should be run as
    # bin/django runserver
    log = Logger("Summary:", "DEBUG")
    context = {
        'page_title': 'Summary of the uploaded pcaps',
    }
    user_id = request.user.id
    #session_key = request.session.session_key
    # TODO: i better keep the user id, login requirements is necessary in this case, for a temporary time use the development USER_ID definition
    url = "".join([settings.BASE_URL, "/api/protocols/?format=json&user_id=", str(user_id)])
    log.message("URL: %s" % (url))
    req = urllib2.Request(url, None)
    opener = urllib2.build_opener()
    f = None
    try:
        f = opener.open(req)
        json_response = json.load(f)
        user_id = user_id

        result = []
        response_dict = dict()
        legend = []
        protocols_found = []

        for response in json_response:
            # indeed i have only one response for now, i decided to put all responses in one timeline instead of multiple timelines
            id = os.urandom(4)
            response_dict["id"] = "".join([id.encode('hex'), str(user_id)])
            response_dict['title'] = "Summary For the Uploaded PCAPs"
            response_dict['focus_date'] = None # will be fixed
            response_dict['initial_zoom'] = "37"

            time_keeper = {'start': None, 'end': None}

            # events creation starts here
            events = []
            for protocol, values in response.iteritems():
                count = 0
                for value in values:
                    event_dict = dict()
                    event_dict['id'] = "-".join([response_dict["id"], protocol, str(count)])
                    if value.has_key("type") and value['type']:
                        event_dict['title'] = value['type']
                    else:
                        event_dict['title'] = protocol
                    if value.has_key('description') and value['description']:
                        event_dict['description'] = cgi.escape(value['description'])
                    else:
                        event_dict['description'] = "No description is set"
                    event_dict['startdate'] = value['start']
                    event_dict['enddate'] = value['end']

                    dt_start = datetime.datetime.strptime(value['start'], "%Y-%m-%d %H:%M:%S")
                    dt_end = datetime.datetime.strptime(value['end'], "%Y-%m-%d %H:%M:%S")
                    if not time_keeper['start']:
                        time_keeper['start'] = dt_start
                    if dt_start <= time_keeper['start']:
                        time_keeper['start'] = dt_start
                    if not time_keeper['end']:
                        time_keeper['end'] = dt_end
                    if dt_end >= time_keeper['end']:
                        time_keeper['end'] = dt_end

                    event_dict['date_display'] = 'day'
                    ts = int(datetime.datetime.strptime(value['end'], "%Y-%m-%d %H:%M:%S").strftime("%s"))
                    importance = repr(translate_time(ts))
                    event_dict['importance'] = importance
                    if protocol not in protocols_found:
                        protocols_found.append(protocol)
                    event_dict['icon'] = ICONS[protocol]
                    events.append(event_dict)
                    count += 1
            response_dict['events'] = events
            # calculate the middle of the time
            mid_point = time_keeper['start'] + ((time_keeper['end'] - time_keeper['start']) / 2)
            response_dict['focus_date'] = mid_point.isoformat(sep=" ")

            for proto in protocols_found:
                tmp = dict()
                tmp['title'] = repr(proto)
                tmp['icon'] = ICONS[proto]
                legend.append(tmp)

            response_dict['legend'] = legend
            result.append(response_dict)

        json_data = json.dumps(result)
        json_dir = os.path.join(settings.PROJECT_ROOT, "json_files")
        json_file = tempfile.NamedTemporaryFile(mode="w", dir=json_dir, delete=False)

        user_json_file = UserJSonFile.objects.filter(user_id=user_id)
        if len(user_json_file) > 0:
            user_json_file[0].delete()
            file_path = os.path.join(settings.PROJECT_ROOT, "json_files", user_json_file[0].json_file_name)
            try:
                os.unlink(file_path)
            except:
                pass

        file_name = os.path.basename(json_file.name)
        # save the json data to the temporary file
        json_file.write(json_data)
        json_file.close()
        user_json_file = UserJSonFile(user_id=user_id, json_type="summary", json_file_name=file_name)
        user_json_file.save()
        context['json_file_url'] = os.path.join(settings.ALTERNATE_BASE_URL, "json_media", file_name)
        context['icon_folder']  = os.path.join(settings.ALTERNATE_BASE_URL, "/site_media/jquery_widget/js/timeglider/icons/")
        context['pcap_operation'] = "summary"

        return render_to_response("pcap/summary.html",
                context_instance=RequestContext(request, context))
        #HttpResponse(json.dumps(response_dict))

    except Exception, ex:
        log.message(ex)
        raise Http404






