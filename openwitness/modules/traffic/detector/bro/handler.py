#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from openwitness.modules.traffic.log.logger import Logger
from django.conf import settings

import subprocess
import os

class Handler:
    def __init__(self):
        self.log = Logger("Bro Handler", "DEBUG")
        self.log.message("bro handler called")
        self.bro_cmd = settings.BRO_CMD
        self.bro_cut_cmd = settings.BRO_CUT_CMD

    def detect(self, file_path, file_dir):
        self.log.message("file_path: %s file_dir: %s" % (file_path, file_dir))
        cmd = " ".join([self.bro_cmd, "-C -r", file_path])
        self.log.message("Bro command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        cmd = " ".join(["cat conn.log", "|", self.bro_cut_cmd, "proto"])
        self.log.message("Bro-cut command: %s" % cmd)
        output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, cwd=file_dir).communicate()[0]
        return output

