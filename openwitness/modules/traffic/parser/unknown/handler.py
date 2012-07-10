from openwitness.modules.traffic.log.logger import Logger
import os
import datetime


class Handler(object):
    def __init__(self):
        super(Handler, self).__init__()

    def get_flow_ips(self, **args):
        result = self.read_conn_log(args['path'])
        return result

    def read_conn_log(self, path):
        result = [] # lets the keys the connection id, values the ts
        conn_log_path = os.path.join(path, "conn.log")
        f = open(conn_log_path, "r")
        for line in f.readlines():
            if line.startswith("#"): continue
            info = line.split()
            tmp = info[2:6]
            dt = datetime.datetime.fromtimestamp(float(info[0]))
            tmp.append(dt)
            result.append(dt)

        return result