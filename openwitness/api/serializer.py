from tastypie.serializers import Serializer
from django.core.serializers import json
from django.utils import simplejson
import datetime

from openwitness.pcap.models import Flow, PacketDetails, HTTPDetails, DNSRequest, DNSResponse, SMTPDetails
from openwitness.modules.utils.handler import translate_value

class CustomJSONSerializer(Serializer):
    def to_json(self, data, options=None):
        options = options or {}

        data = self.to_simple(data, options)

        # Add in the current time.
        #data['requested_time'] = time.time()
        result = []
        protocol_dict = dict()
        if not data.has_key('objects'): return {}
        for flow in data['objects']:
            if flow['protocol'] == "http":
                # get the start and end time for this flow
                start, end = self.get_start_end(flow)
                type, description = self.get_http_info(flow)
                tmp = dict()
                tmp['flow_id'] = flow['id']
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("http"):
                    protocol_dict["http"].append(tmp)
                else:
                    protocol_dict["http"] = [tmp]

            if flow['protocol'] == "dns":
                start, end = self.get_start_end(flow)
                type, description = self.get_dns_info(flow)
                tmp = dict()
                tmp['flow_id'] = flow['id']
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("dns"):
                    protocol_dict["dns"].append(tmp)
                else:
                    protocol_dict["dns"] = [tmp]

            if flow['protocol'] == "smtp":
                start, end = self.get_start_end(flow)
                type, description = self.get_smtp_info(flow)
                tmp = dict()
                tmp['flow_id'] = flow['id']
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("smtp"):
                    protocol_dict["smtp"].append(tmp)
                else:
                    protocol_dict["smtp"] = [tmp]

            if flow['protocol'] == "unknown":
                start, end = self.get_start_end(flow)
                type, description = "unknown", ""
                tmp = dict()
                tmp['flow_id'] = flow['id']
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("unknown"):
                    protocol_dict["unknown"].append(tmp)
                else:
                    protocol_dict["unknown"] = [tmp]

        result.append(protocol_dict)
        data = result
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder, sort_keys=True)

    def from_json(self, content):
        data = simplejson.loads(content)

        #if 'requested_time' in data:
            # Log the request here...
        #    pass

        return data

    # TODO: for udp, packet details are not saved
    def get_start_end(self, flow):
        packets = PacketDetails.objects.filter(src_ip=flow['src_ip'], sport=flow['sport'], dst_ip=flow['dst_ip'], dport=flow['dport']).order_by('timestamp')
        return packets[0].timestamp, packets[len(packets)-1].timestamp


    def get_http_info(self, flow):
        http_all = HTTPDetails.objects.all()
        flow_details = filter(lambda x: x.flow_details.id == flow['id'], http_all) # this should be returning only one
        if len(flow_details) > 0:
            info = flow_details[0]
            type = info.http_type
            description = None
            if type == "request":
                description = " ".join([info.uri, "HTTP", str(info.version)])
            if type == "response":
                description = ""
                if info.status:
                    description = " ".join([description, str(info.status)])
                if info.content_type:
                    description = " ".join([description, str(info.content_type)])
                if info.content_encoding:
                    description = " ".join([description, str(info.content_encoding)])
            return type, description
        return None, None

    def get_dns_info(self, flow):
        dns_request_all = DNSRequest.objects.all()
        flow_details = filter(lambda x: x.flow_details.id == flow['id'], dns_request_all)
        if len(flow_details) > 0:
            info = flow_details[0]
            type = "DNS Request"
            description = " ".join([info.human_readable_type, info.value])
            return type, description
        dns_response_all = DNSResponse.objects.all()
        flow_details = filter(lambda x: x.flow_details.id == flow['id'], dns_response_all)
        if len(flow_details) > 0:
            info = flow_details[0]
            type = "DNS Response"
            description = " ".join([info.human_readable_type, info.value])
            return type, description
        return None, None

    def get_smtp_info(self, flow):
        smtp_details_all = SMTPDetails.objects.all()
        flow_details = filter(lambda x: x.flow_details.id == flow['id'], smtp_details_all)
        if len(flow_details) > 0:
            info = flow_details[0]
            type = "SMTP"
            description = " ".join(["FROM:", info.msg_from, "TO:", info.rcpt_to])
            return type, description
        return None, None

class AppProtocolPacketSizeCustomJSONSerializer(Serializer):
    def to_json(self, data, options=None):
        options = options or {}

        data = self.to_simple(data, options)

        result = dict()
        if not data.has_key('objects'): return {}
        for flow in data['objects']:
            flow_dict = dict()
            src_ip = flow['src_ip']
            sport = flow['sport']
            s_combined = ":".join([src_ip, str(sport)])
            dst_ip = flow['dst_ip']
            dport = flow['dport']
            d_combined = ":".join([dst_ip, str(dport)])
            hash_value = flow['parent_hash_value']
            parent_flow = Flow.objects.get(hash_value=hash_value)
            if not result.has_key(parent_flow.file_name):
                result['name'] = parent_flow.file_name
            if not result.has_key('children'):
                result['children'] = []
            flow_dict['name'] = "-".join([s_combined, d_combined])
            packets = PacketDetails.objects.filter(src_ip=src_ip, sport=sport, dst_ip=dst_ip, dport=dport)
            flow_dict['children'] = []
            for p in packets:
                #src_id = ":".join([p.src_ip, str(p.sport)])
                #dst_id = ":".join([p.dst_ip, str(p.dport)])
                #id = "-".join([src_id, dst_id])
                flow_dict['children'].append({'name': str(p.ident), 'size':p.length})
            result['children'].append(flow_dict)

        data = result
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder, sort_keys=True)

    def from_json(self, content):
        data = simplejson.loads(content)

        return data

class AppProtocolPacketCountCustomJSONSerializer(Serializer):
    def to_json(self, data, options=None):
        options = options or {}

        data = self.to_simple(data, options)

        result = dict()
        if not data.has_key('objects'): return {}
        for flow in data['objects']:
            flow_dict = dict()
            src_ip = flow['src_ip']
            sport = flow['sport']
            s_combined = ":".join([src_ip, str(sport)])
            dst_ip = flow['dst_ip']
            dport = flow['dport']
            d_combined = ":".join([dst_ip, str(dport)])
            hash_value = flow['parent_hash_value']
            parent_flow = Flow.objects.get(hash_value=hash_value)
            if not result.has_key(parent_flow.file_name):
                result['name'] = parent_flow.file_name
            if not result.has_key('children'):
                result['children'] = []
            flow_dict['name'] = "-".join([s_combined, d_combined])
            packets = PacketDetails.objects.filter(src_ip=src_ip, sport=sport, dst_ip=dst_ip, dport=dport)
            flow_dict['children'] = []
            flow_dict['children'].append({'name': str(packets[0].ident), 'size':len(packets)})
            result['children'].append(flow_dict)

        data = result
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder, sort_keys=True)

    def from_json(self, content):
        data = simplejson.loads(content)

        return data

class AllProtocolsJSONSerializer(Serializer):
    def to_json(self, data, options=None):
        options = options or {}

        data = self.to_simple(data, options)

        result = []
        protocol_dict = dict()
        if not data.has_key('objects'): return {}
        for flow in data['objects']:
            protocol = flow['protocol']
            dt = flow['timestamp'].split(".")[0]
            dt_object = datetime.datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S')
            ts = int(dt_object.year)
            #{ 2011: {'http': 11} }
            if protocol_dict.has_key(ts):
                if protocol_dict[ts].has_key(protocol):
                    protocol_dict[ts][protocol] += 1
                else:
                    protocol_dict[ts][protocol] =  1

            else:
                protocol_dict[ts] = dict()
                protocol_dict[ts] = {protocol: 1}

        min_max_count = []
        for year, v in protocol_dict.items():
            for proto, count in v.items():
                min_max_count.append(count)
        min_max_count.sort()
        for year, v in protocol_dict.items():
            for proto, count in v.items():
                d = dict()
                d['key'] = proto
                if not d.has_key('values'):
                    d['values'] = []
                values = dict()
                values['x'] = year
                left_min = 0
                left_max = 0
                if len(min_max_count) == 1:
                    left_min = 0
                    left_max = min_max_count[0]
                else:
                    left_min = min_max_count[0]
                    left_max = min_max_count[-1]

                values['y'] = count #translate_value(count, left_min, left_max, 1, 50) # let the y between 1 - 50
                values['size'] = translate_value(count, left_min, left_max, 1, 100) # lets map the size between 1 and 50 by taking into consideration the count
                values['shape'] = 'circle'
                d['values'].append(values)

                result.append(d)

        # lets also check TCP and UPD statistics
        protocol_dict = dict()
        packets = PacketDetails.objects.all()
        protocol_no = {6: 'TCP', 17: 'UDP'}
        for packet in packets:
            ts = int(packet.timestamp.year)
            protocol = protocol_no[packet.protocol]
            if protocol_dict.has_key(ts):
                if protocol_dict[ts].has_key(protocol):
                    protocol_dict[ts][protocol] += 1
                else:
                    protocol_dict[ts][protocol] = 1

            else:
                protocol_dict[ts] = dict()
                protocol_dict[ts] = {protocol: 1}


        min_max_count = []
        for year, v in protocol_dict.items():
            for proto, count in v.items():
                min_max_count.append(count)
        min_max_count.sort()
        for year, v in protocol_dict.items():
            for proto, count in v.items():
                d = dict()
                d['key'] = proto
                if not d.has_key('values'):
                    d['values'] = []
                values = dict()
                values['x'] = year
                values['y'] = count #translate_value(count, min_max_count[0], min_max_count[-1], 1, 50) # let the y between 1 - 50
                if len(min_max_count) == 1:
                    left_min = 0
                    left_max = min_max_count[0]
                else:
                    left_min = min_max_count[0]
                    left_max = min_max_count[-1]
                values['size'] = translate_value(count, left_min, left_max, 1, 100) # lets map the size between 1 and 50 by taking into consideration the count
                values['shape'] = 'triangle-up'
                d['values'].append(values)

                result.append(d)

        data = result
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder, sort_keys=True)

    def from_json(self, content):
        data = simplejson.loads(content)

        return data
