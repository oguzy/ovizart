from openwitness.modules.traffic.log.logger import Logger
import os
import datetime
from openwitness.pcap.models import FlowDetails


class Handler(object):
    def __init__(self):
        super(Handler, self).__init__()

    def get_flow_ips(self, **args):
        result = self.read_conn_log(args['path'], args['parent_hash_value'], args['user_id'])
        return result

    def read_conn_log(self, path, parent_hash_value, user_id):
        result = [] # lets the keys the connection id, values the ts
        conn_log_path = os.path.join(path, "conn.log")
        f = open(conn_log_path, "r")
        for line in f.readlines():
            if line.startswith("#"): continue
            info = line.split()
            tmp = info[2:6]
            dt = datetime.datetime.fromtimestamp(float(info[0]))
            tmp.append(dt)

            check = FlowDetails.objects.filter(parent_hash_value=parent_hash_value, user_id=user_id, src_ip=tmp[0], sport=int(tmp[1]),
                                        dst_ip=tmp[2], dport=int(tmp[3]))

            if len(check,) > 0:
                continue

            result.append(tmp)

        return result