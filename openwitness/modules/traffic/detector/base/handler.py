#!/usr/bin/env python
#-*- coding: UTF-8 -*-


from openwitness.modules.traffic.log.logger import Logger


class Handler(object):
    def __init__(self):
        super(Handler, self).__init__()
        self.log = Logger("Base Protocol Handler", "DEBUG")
        self.log.message("base protocol handler called")

    def detect(self,**params):
        pass

