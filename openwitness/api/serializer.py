from tastypie.serializers import Serializer
from django.core.serializers import json
import simplejson

from openwitness.pcap.models import PacketDetails, HTTPDetails, DNSRequest, DNSResponse, SMTPDetails

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
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("http"):
                    protocol_dict["http"].append(tmp)
                else:
                    protocol_dict["http"] = [tmp]

            # TODO: it doesn't return type and description somehow, check it
            if flow['protocol'] == "dns":
                start, end = self.get_start_end(flow)
                type, description = self.get_dns_info(flow)
                tmp = dict()
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
                tmp["start"] = start
                tmp["end"] = end
                if type and description:
                    tmp["type"] = type
                    tmp["description"] = description
                if protocol_dict.has_key("smtp"):
                    protocol_dict["smtp"].append(tmp)
                else:
                    protocol_dict["smtp"] = [tmp]
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