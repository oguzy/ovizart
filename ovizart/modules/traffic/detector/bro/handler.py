#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from ovizart.modules.traffic.detector.base.handler import Handler as BaseHandler
from django.conf import settings

import subprocess
import os

BRO_CMD = settings.BRO_CMD
BRO_CUT_CMD = settings.BRO_CUT_CMD

class Handler(BaseHandler):
    def __init__(self):
        super(Handler, self).__init__()
        self.bro_cmd = BRO_CMD
        self.bro_cut_cmd = BRO_CUT_CMD

    def create_reassemble_information(self, file_path, file_dir):
        # i had used -C to skip the checksum issue but with this command i got some errors on some pcaps
        cmd = " ".join([self.bro_cmd, "-r", file_path])
        self.log.message("Bro command: %s" % cmd)
        # this command will create dat files for each contents and log for each communication level data
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        return output

    def detect_proto(self, file_path, file_dir):
        cmd = " ".join(["cat conn.log", "|", self.bro_cut_cmd, "proto"])
        self.log.message("Bro-cut command: %s" % cmd)
        try:
            output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
            return output.split("\n")
        except:
            return False

    def detect_appproto(self, file_path, file_dir):
        #check whether there exists any of the following log files is so return it
        protos = ['http', 'ftp', 'smtp', 'dns']
        output = filter(lambda x: os.path.exists("/".join([file_dir, ".".join([x, "log"])])), protos)
        if output:
            return output

        # not every time i have application_layer_proto.log, use tshark
        pre_cmd = " ".join(["tshark -q -z io,phs, -r", file_path, "| grep"])
        for proto in protos:
            cmd = " ".join([pre_cmd, proto])
            output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
            if output:
                return output.split()[0]

        # the last option is to use the conn.log information
        cmd = " ".join(["cat conn.log", "|", self.bro_cut_cmd, "service"])
        self.log.message("Bro-cut command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        result = filter(lambda x: x in output.split('\n'), protos)
        if result:
            return result
        return False

