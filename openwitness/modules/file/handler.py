#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import datetime
import os
from django.conf import settings
from openwitness.modules.traffic.log.logger import Logger

from openwitness.modules.utils.handler import generate_name_from_timestame
#hachoir related imports
from hachoir_core.cmd_line import unicodeFilename
from hachoir_core.stream import FileInputStream
from hachoir_regex.pattern import PatternMatching

class Handler:
    def __init__(self):
        self.file_path = None
        self.file_name = None
        self.stream = None
        self.data = None
        self.log = Logger("File Handler", "DEBUG")

    def create_dir(self):
        now = datetime.datetime.now()
        self.log.message("Now is: %s:" % now)
        directory_name = now.strftime("%d-%m-%y")
        self.log.message("Directory name: %s:" % directory_name)
        directory_path = "/".join([settings.PROJECT_ROOT, "uploads", directory_name])
        self.log.message("Directory path: %s" % directory_path)
        if not os.path.exists(directory_path):
            os.mkdir(directory_path)
            self.log.message("Directory created")
        # we need to create another directory also for each upload
        new_dir = generate_name_from_timestame()
        new_dir_path = "/".join([directory_path, new_dir])
        if not os.path.exists(new_dir_path):
            os.mkdir(new_dir_path)
            self.log.message("Directory created")
        self.upload_dir = new_dir_path

    def save_file(self, f):
        self.file_name = f.name
        self.file_path = "/".join([self.upload_dir, self.file_name])
        destination = open(self.file_path, 'wb+')
        for chunk in f.chunks():
            destination.write(chunk)
        destination.close()

    def search(self, file_path, strings=None):
        self.stream = FileInputStream(unicodeFilename(file_path), real_filename=file_path)
        patterns = PatternMatching()
        for s in strings:
            patterns.addString(s)

        start = 0
        end = self.stream.size
        self.data = self.stream.readBytes(start, end//8)
        return patterns.search(self.data)

    def reset_data(self):
        self.data = None