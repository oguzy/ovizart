#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import subprocess
import os

class Handler:
    def __init__(self):
        os.environ["PATH"] = "/usr/local/bro/bin:" + os.getenv("PATH")

    def detect(self, file_path, file_dir):
        cmd = " ".join(["bro -C -r", file_path])
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=file_dir).communicate()[0]
        cmd = "cat conn.log | bro-cut proto"
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=file_dir).communicate()[0]
        return output

