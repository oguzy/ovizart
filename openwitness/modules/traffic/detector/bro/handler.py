#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from openwitness.modules.traffic.detector.base.handler import Handler as BaseHandler

import subprocess

BRO_CMD = "/usr/local/bro/bin/bro"
BRO_CUT_CMD = "/usr/local/bro/bin/bro-cut"

class Handler(BaseHandler):
    def __init__(self):
        super(Handler, self).__init__()
        self.bro_cmd = BRO_CMD
        self.bro_cut_cmd = BRO_CUT_CMD

    def detect_proto(self, file_path, file_dir):
        self.log.message("file_path: %s file_dir: %s" % (file_path, file_dir))
        cmd = " ".join([self.bro_cmd, "-C -r", file_path])
        self.log.message("Bro command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        cmd = " ".join(["cat conn.log", "|", self.bro_cut_cmd, "proto"])
        self.log.message("Bro-cut command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        return output

    def detect_appproto(self, file_path, file_dir):
        self.log.message("file_path: %s file_dir: %s" % (file_path, file_dir))
        cmd = " ".join([self.bro_cmd, "-C -r", file_path])
        self.log.message("Bro command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        cmd = " ".join(["cat conn.log", "|", self.bro_cut_cmd, "service"])
        self.log.message("Bro-cut command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        return output

