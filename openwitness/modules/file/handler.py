#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import datetime
import os
from django.conf import settings

class Handler:
    def __init__(self):
        now = datetime.datetime.now()
        directory_name = now.strftime("%d-%m-%y")
        directory_path = "/".join([settings.PROJECT_ROOT, directory_name])
        if not os.path.exists(directory_path):
            os.mkdir(directory_path)
        self.upload_dir = directory_path

    def save_file(self, f):
        self.file_path = self.upload_dir + f.name
        destination = open(file_path, 'wb+')
        for chunk in f.chunks():
            destination.write(chunk)
        destination.close()
