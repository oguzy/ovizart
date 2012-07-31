# Create your views here.

import hashlib
import urllib2
import tempfile
import os
import datetime
import cgi
import magic
#import random
from django.http import Http404, HttpResponse
from django.utils import simplejson as json
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.core.urlresolvers import reverse
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

from openwitness.pcap.models import Flow, Pcap, PacketDetails, FlowDetails, HTTPDetails, DNSRequest, DNSResponse, SMTPDetails
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
        'upload_status': False,
        'message': request.session.get('message', False)
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
            hash_value = hash_handler.get_hash(os.path.join(upload_path, pcap_name))
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

            if output == False:
                request.session['message'] = "Error occured. Please try again."
                return redirect('/pcap/upload')

            flow_file, created = Flow.objects.get_or_create(user_id=user_id, hash_value=hash_value,file_name=pcap_name, path=upload_path)

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
                pcap_list = map(lambda x: Pcap.objects.create(hash_value=hash_handler.get_hash(os.path.join(upload_path, x)), file_name=x, path=upload_path), files.values()[0])
                if flow_file.pcaps:
                    pre_li = flow_file.pcaps
                    pre_li.extend(pcap_list)
                    flow_file.pcaps = pre_li
                else:
                    flow_file.pcaps = pcap_list
                flow_file.save()

                p_read_handler.close_file()
                p_write_handler.close_file()
                # now i should hook a protocol detector
                # before that i should detect the application level protocol
                for f in files.values()[0]:
                    packets  = []
                    # better to save tcp level information to db here
                    full_path = os.path.join(upload_path, f)
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
                        tcp_data = u"."
                        if tcp_handler.data:
                            tcp_data = tcp_handler.data
                            # some requests include hexadecimal info, most probably some binary info that can not be
                            # converted to the utf8, for now i better remove them, #TODO should handle them, though
                            # try with 4, tcp.data has binary request
                            # def get_tcp(n):
                            #    count = 1
                            #    f = file("milliyet.pcap", "rb")
                            #    reader = dpkt.pcap.Reader(f)
                            #    for ts, buf in reader:
                            #        if count == n:
                            #            f.close()
                            #            return buf
                            #        count += 1

                            data_li = tcp_data.split("\r\n")
                            tmp = []
                            for data in data_li:
                                try:
                                    data.encode("utf-8")
                                    tmp.append(data)
                                except:
                                    tmp.append("data that can not be encoded to utf-8")

                            tcp_data = " \n".join(tmp)

                        packet = PacketDetails.objects.create(ident=tcp_handler.ident, timestamp=tcp_handler.timestamp,
                                                                length=tcp_handler.length, protocol=tcp_handler.proto,
                                                                src_ip=tcp_handler.src_ip,
                                                                dst_ip=tcp_handler.dst_ip, sport=tcp_handler.sport,
                                                                dport=tcp_handler.dport, data=str(tcp_data))
                        packets.append(packet)
                    # get the pcap object
                    p = Pcap.objects.get(hash_value=hash_handler.get_hash(os.path.join(upload_path, f)))
                    log.message("pcap for packet update detected: %s" % p)
                    # update its packets
                    p.packets = list(packets) # converting a queryset to list
                    p.save()
                    p_read_handler.close_file()

            if "udp" in output:
                log.message("protocol detected: %s" % "UDP")
                p_read_handler = PcapHandler()
                file_path = os.path.join(upload_path, pcap_name)
                p_read_handler.open_file(file_path)
                p_read_handler.open_pcap()
                udp_handler = UDPHandler()
                pcap = Pcap.objects.create(hash_value=hash_handler.get_hash(os.path.join(upload_path, pcap_name)), file_name=pcap_name, path=upload_path)
                pcap_list = list([pcap])
                if flow_file.pcaps:
                    pre_li = flow_file.pcaps
                    pre_li.extend(pcap_list)
                    flow_file.pcaps = pre_li
                else:
                    flow_file.pcaps = pcap_list
                flow_file.save()

                packets  = []
                for ts, buf in p_read_handler.get_reader():
                    udp = udp_handler.read_udp(ts, buf)
                    if udp:
                        udp_data = u"."
                        if udp_handler.data:
                            udp_data = udp_handler.data
                            try:
                                udp_data = udp_data.encode("utf-8")
                            except:
                                udp_data = "data that can not be encoded to utf-8"
                        packet = PacketDetails.objects.create(ident=udp_handler.ident, timestamp=udp_handler.timestamp,
                                                            length = udp_handler.length,
                                                            protocol=udp_handler.proto, src_ip=udp_handler.src_ip,
                                                            dst_ip=udp_handler.dst_ip, sport=udp_handler.sport,
                                                            dport=udp_handler.dport, data=str(udp_data))
                        packets.append(packet)
                        # get the pcap object
                p = Pcap.objects.get(hash_value=hash_handler.get_hash(os.path.join(upload_path, pcap_name)))
                # update its packets
                p.packets = list(packets) # converting a queryset to list
                p.save()
                p_read_handler.close_file()


            # starting the bro related issues for the reassembled data
            output = traffic_detector_handler.detect_appproto(file_handler.file_path, upload_path)
            log.message("protocol detected: %s" % output)
            if output and "http" in output:
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
                if flow_file.details:
                    pre_li = flow_file.details
                    pre_li.extend(flow_detail_li)
                    flow_file.details = pre_li
                else:
                    flow_file.details = flow_detail_li
                flow_file.save()
                # then call functions that will save request and responses that will parse dat files, save the headers and files
                #http_handler.save_request(path=upload_path, hash_value=request.session['uploaded_hash'])
                #http_handler.save_response(path=upload_path, hash_value=request.session['uploaded_hash'])
                http_handler.save_request_response(path=upload_path, hash_value=request.session['uploaded_hash'])

            # dns realted issues starts here
            if output and "dns" in output:
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
                if flow_file.details:
                    pre_li = flow_file.details
                    pre_li.extend(flow_detail_li)
                    flow_file.details = pre_li
                else:
                    flow_file.details = flow_detail_li
                flow_file.save()

                dns_handler.save_request_response()

            if output and "smtp" in output:
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
                if flow_file.details:
                    pre_li = flow_file.details
                    pre_li.extend(flow_detail_li)
                    flow_file.details = pre_li
                else:
                    flow_file.details = flow_detail_li
                flow_file.save()

                smtp_handler.save_request_response(upload_path=upload_path)

            else:
                log.message("protocol detected: %s" % "Unknown")
                unknown_protocol_handler = settings.UNKNOWN_HANDLER
                package = "openwitness.modules.traffic.parser"
                module_name = ".".join([package, unknown_protocol_handler])
                unknown_handler_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                unknown_handler = unknown_handler_module.Handler()
                flow_ips = unknown_handler.get_flow_ips(path=upload_path, file_name=request.session['uploaded_file_name'], parent_hash_value=request.session['uploaded_hash'], user_id=user_id)
                flow_detail_li = []
                for detail in flow_ips:
                    flow_detail, create = FlowDetails.objects.get_or_create(parent_hash_value=request.session['uploaded_hash'], user_id=user_id, src_ip=detail[0], sport=int(detail[1]), dst_ip=detail[2], dport=int(detail[3]), protocol="unknown", timestamp = detail[4])
                    if created:
                        flow_detail_li.append(flow_detail)

                if flow_file.details:
                    pre_li = flow_file.details
                    pre_li.extend(flow_detail_li)
                    flow_file.details = pre_li
                else:
                    flow_file.details = flow_detail_li
                flow_file.save()



    else:
        form = UploadPcapForm()
        context['form'] = form

    request.session['message'] = False
    return render_to_response("pcap/upload.html",
            context_instance=RequestContext(request, context))

@login_required()
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
    url = "".join([settings.BASE_URL, "/api/rest/protocols/?format=json&user_id=", str(user_id)])
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
            response_dict['initial_zoom'] = "38"

            time_keeper = {'start': None, 'end': None}
            importance_keeper = []

            # events creation starts here
            events = []
            for protocol, values in response.iteritems():
                count = 0
                for value in values:
                    event_dict = dict()
                    event_dict['id'] = "-".join([response_dict["id"], protocol, str(count)])
                    event_dict['link'] = reverse('flow_details', args=(value['flow_id'],))
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
                    ts = int(datetime.datetime.strptime(value['start'], "%Y-%m-%d %H:%M:%S").strftime("%s"))
                    importance = translate_time(ts)
                    #importance = random.randrange(1, 100)
                    event_dict['importance'] = importance
                    event_dict['high_threshold'] = int(importance) + 5
                    importance_keeper.append(int(importance))
                    if protocol not in protocols_found:
                        protocols_found.append(protocol)
                    event_dict['icon'] = ICONS[protocol]
                    events.append(event_dict)
                    count += 1
            response_dict['events'] = events
            # calculate the middle of the time
            mid_point = time_keeper['start'] + ((time_keeper['end'] - time_keeper['start']) / 2)
            response_dict['focus_date'] = mid_point.isoformat(sep=" ")

            # calculate initial zoom
            response_dict['initial_zoom'] = repr(int((importance_keeper[0]+importance_keeper[-1])/2))

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

        user_json_file = UserJSonFile.objects.filter(user_id=user_id, json_type="summary")
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

        # get the summary query infos
        flow = Flow.objects.filter(user_id=request.user.id)
        context['flow'] = flow

        flow_details = FlowDetails.objects.filter(user_id=request.user.id)
        flow_details_dict = dict()

        f_d = dict()
        for flow_detail in flow_details:
            if not flow_details_dict.has_key(flow_detail.protocol):
                flow_details_dict[flow_detail.protocol] = dict()
                f_d = flow_details_dict[flow_detail.protocol]
                f_d['count'] = 1
                f_d['timestamps'] = [flow_detail.timestamp]
            else:
                f_d['count'] += 1
                f_d['timestamps'].append(flow_detail.timestamp)

        for key, value in flow_details_dict.items():
            ts = flow_details_dict[key]['timestamps']
            ts.sort()
            flow_details_dict[key]['start'] = ts[0]
            flow_details_dict[key]['end'] = ts[-1]

        context['flow_details'] = flow_details_dict
        context['ALTERNATE_BASE_URL'] = settings.ALTERNATE_BASE_URL


        return render_to_response("pcap/summary.html",
                context_instance=RequestContext(request, context))
        #HttpResponse(json.dumps(response_dict))

    except Exception, ex:
        log.message(ex)
        raise Http404

@login_required()
def visualize(request, protocol, type="size"):
    if type == "size":
        # to get this work, runserver should be run as bin/django runserver 127.0.0.0:8001 and another instance should be run as
        # bin/django runserver
        log = Logger("Visualize:", "DEBUG")
        context = {
            'page_title': 'Packet Sizes of the uploaded pcaps',
            }
        user_id = request.user.id
        url = "".join([settings.BASE_URL, "/api/rest/protocol_size/?format=json&user_id=", str(user_id), "&protocol=", protocol])
        log.message("URL: %s" % (url))
        req = urllib2.Request(url, None)
        opener = urllib2.build_opener()
        f = None
        try:
            f = opener.open(req)
            json_response = json.load(f)
            json_data = json.dumps(json_response)

            context['children'] = json_response['children']
            context['flow_details'] = json_response
            context['pcap_operation'] = "summary-size"

            json_dir = os.path.join(settings.PROJECT_ROOT, "json_files")
            json_file = tempfile.NamedTemporaryFile(mode="w", dir=json_dir, delete=False)

            user_json_file = UserJSonFile.objects.filter(user_id=user_id, json_type="summary-size")
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
            user_json_file = UserJSonFile(user_id=user_id, json_type="summary-size", json_file_name=file_name)
            user_json_file.save()
            context['json_file_url'] = os.path.join(settings.ALTERNATE_BASE_URL, "json_media", file_name)

            context['measure'] = 'size'

            return render_to_response("pcap/summary-size.html",
        context_instance=RequestContext(request, context))

        except:
            # return html template
            pass
    else:
        # to get this work, runserver should be run as bin/django runserver 127.0.0.0:8001 and another instance should be run as
        # bin/django runserver
        log = Logger("Visualize:", "DEBUG")
        context = {
            'page_title': 'Packet counts of the uploaded pcaps',
            }
        user_id = request.user.id
        url = "".join([settings.BASE_URL, "/api/rest/protocol_count/?format=json&user_id=", str(user_id), "&protocol=", protocol], )
        log.message("URL: %s" % (url))
        req = urllib2.Request(url, None)
        opener = urllib2.build_opener()
        f = None
        try:
            f = opener.open(req)
            json_response = json.load(f)

            json_data = json.dumps(json_response)
            context['children'] = json_response['children']
            context['flow_details'] = json_response
            context['pcap_operation'] = "summary-size"

            json_dir = os.path.join(settings.PROJECT_ROOT, "json_files")
            json_file = tempfile.NamedTemporaryFile(mode="w", dir=json_dir, delete=False)

            user_json_file = UserJSonFile.objects.filter(user_id=user_id, json_type="summary-size")
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
            user_json_file = UserJSonFile(user_id=user_id, json_type="summary-size", json_file_name=file_name)
            user_json_file.save()
            context['json_file_url'] = os.path.join(settings.ALTERNATE_BASE_URL, "json_media", file_name)

            return render_to_response("pcap/summary-size.html",
                context_instance=RequestContext(request, context))

        except:
            # return html template
            pass

def flow_details(request, flow_id):
    flow_details = FlowDetails.objects.get(id=flow_id)

    result = []

    if flow_details.protocol == "http":
        http_details = filter(lambda x: x.flow_details.id == flow_details.id, HTTPDetails.objects.all())
        for http_detail in http_details:
            http_dict = dict()

            http_dict['protocol'] = 'HTTP'
            if http_detail.http_type:
                http_dict['http_type'] = http_detail.http_type
            if http_detail.method:
                http_dict['method'] = http_detail.method
            if http_detail.uri:
                http_dict['uri'] = http_detail.uri
            if http_detail.headers:
                headers = http_detail.headers
                content = headers[1:-1]
                clean_content = map(lambda x: x.replace("'", "").replace("\\r", "").strip(), content.split(","))
                human_readable_header = map(lambda x: str(x), clean_content)
                http_dict['headers'] = human_readable_header
            if http_detail.version:
                http_dict['version'] = http_detail.version
            if http_detail.reason:
                http_dict['reason'] = http_detail.reason
            if http_detail.status:
                http_dict['status'] = http_detail.status
            if http_detail.body:
                http_dict['body'] = http_detail.body
            if http_detail.content_type:
                http_dict['content_type'] = http_detail.content_type
            if http_detail.content_encoding:
                http_dict['content_encoding'] = http_detail.content_encoding
            if http_detail.file_path:
                # i don't keep the file names at the db but at the directories created according to the flow information
                flow_details = http_detail.flow_details
                src_info = ":".join([flow_details.src_ip, str(flow_details.sport)])
                dst_info = ":".join([flow_details.dst_ip, str(flow_details.dport)])
                file_dir = "-".join([src_info, dst_info])
                files = dict()
                files['path'] = os.path.join(http_detail.file_path.split('uploads')[1], file_dir)
                #files['file_list'] = os.listdir(os.path.join(http_detail.file_path, os.path.basename(files['path'])))
                #files['file_list'] = http_detail.files
                http_dict['files'] = files

                protocol_handler = settings.VIRUS_HANDLER
                package = "openwitness.modules.malware"
                module_name = ".".join([package, protocol_handler])
                virus_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                virus_handler = virus_module.Handler()

                malware_dict = dict()
                for f in http_detail.files:
                    path = os.path.join(http_detail.file_path, file_dir, f)
                    rescan_result = virus_handler.rescan(str(path))
                    permalink = ""
                    if rescan_result and rescan_result['response_code'] == 1:
                        permalink = rescan_result['permalink']
                    else:
                        scan_result = virus_handler.scan(str(path))
                        if scan_result and scan_result['response_code'] == 1:
                            report_result = virus_handler.get_report(str(path))
                            if report_result and report_result['response_code'] == 1:
                                permalink = report_result['permalink']

                    malware_dict[f] = permalink

                files['file_list'] = malware_dict

            result.append(http_dict)

    if flow_details.protocol == "dns":
        dns_request= filter(lambda x: x.flow_details.id == flow_details.id, DNSRequest.objects.all())
        for dns_req in dns_request:
            dns_req_dict = dict()
            dns_req_dict['protocol'] = 'DNS Request'
            if dns_req.human_readable_type:
                dns_req_dict['human_readable_type'] = dns_req.human_readable_type
            if dns_req.value:
                dns_req_dict['value'] = dns_req.value

            result.append(dns_req_dict)

        dns_response= filter(lambda x: x.flow_details.id == flow_details.id, DNSResponse.objects.all())
        for dns_res in dns_response:
            dns_res_dict = dict()
            dns_res_dict['protocol'] = 'DNS Request'
            if dns_res.human_readable_type:
                dns_res_dict['human_readable_type'] = dns_res.human_readable_type
            if dns_res.value:
                dns_res_dict['value'] = dns_res.value

            result.append(dns_res_dict)


    if flow_details.protocol == "smtp":
        smtp_details= filter(lambda x: x.flow_details.id == flow_details.id, SMTPDetails.objects.all())
        for smtp_detail in smtp_details:
            smtp_dict = dict()
            smtp_dict['protocol'] = 'SMTP'
            if smtp_detail.login_data:
                smtp_dict['login_data'] = smtp_detail.login_data
            if smtp_detail.msg_from:
                smtp_dict['msg_from'] = smtp_detail.msg_from
            if smtp_detail.rcpt_to:
                smtp_dict['rcpt_to'] = smtp_detail.rcpt_to
            if smtp_detail.raw:
                smtp_dict['raw'] = smtp_detail.raw
            if smtp_detail.msgdata:
                data = smtp_detail.msgdata[1:-1]
                content = data.split(",")
                smtp_dict['msgdata'] = content
            if smtp_detail.attachment_path:
                smtp_dict['attachment_path'] = smtp_detail.attachment_path
                smtp_dict['get_path_dict'] = smtp_detail.get_path_dict()

                attachment_type  = dict()
                # detect the file type for SMTP
                for attachment in smtp_detail.attachment_path:
                    mime = magic.open(magic.MAGIC_MIME)
                    mime.load()
                    attachment_type[os.path.basename(attachment)] = mime.file(attachment)

                protocol_handler = settings.VIRUS_HANDLER
                package = "openwitness.modules.malware"
                module_name = ".".join([package, protocol_handler])
                virus_module = getattr(__import__(module_name, fromlist=["handler"]), "handler")
                virus_handler = virus_module.Handler()


                for path in smtp_detail.attachment_path:
                    rescan_result = virus_handler.rescan(str(path))
                    permalink = ""
                    if rescan_result and rescan_result['response_code'] == 1:
                        permalink = rescan_result['permalink']
                    else:
                        scan_result = virus_handler.scan(str(path))
                        if scan_result and scan_result['response_code'] == 1:
                            report_result = virus_handler.get_report(str(path))
                            if report_result and report_result['response_code'] == 1:
                                permalink = report_result['permalink']

                    base_path = os.path.basename(path)

                    for content in smtp_dict['get_path_dict']:
                        if content['file_name'] == base_path:
                            content['virus_total_link'] = permalink
                            content['file_type'] = attachment_type[base_path]


            result.append(smtp_dict)

    context = dict()
    context['flow_details'] = result
    context['page_title'] = "Flow Details"
    return render_to_response("pcap/flow_details.html",
            context_instance=RequestContext(request, context))

def get_pcap_url(request, id):
    pcap = Pcap.objects.get(id=id)
    html = "".join(["<a href=\"/uploads/", pcap.get_upload_path(), "/", str(pcap.file_name), "\"", ">", str(pcap.file_name), "</a>"])
    return HttpResponse(html)

#TODO: i should display the packet payload data as well
def get_packet_info(request, packet_ident):
    packet = PacketDetails.objects.get(ident=packet_ident)
    context = dict()
    context['packet_details'] = packet
    context['page_title'] = "Packet Details"
    return render_to_response("pcap/packet_details.html",
        context_instance=RequestContext(request, context))

