#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import hashlib

class Handler:
    def __init__(self):
        self._file_name = None

    def set_file(self, file_name):
        self._file_name = file_name

    def get_hash(self, file_name):
        self._file_name = file_name
        md5 = hashlib.md5()
        with open(self._file_name, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
        return md5.hexdigest()

