#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import logging

class Logger:

    def __init__(self, log_name, log_mode):
        logging.basicConfig(format='%(asctime)-6s: %(name)s - %(levelname)s - %(message)s')
        self.mode = log_mode
        self.log = logging.getLogger(log_name)
        self.log.setLevel(log_mode)

    def message(self, message):
        if self.mode == "DEBUG":
            self.log.debug(message)
        if self.mode == "ERROR":
            self.log.error(message)
        if self.mode == "INFO":
            self.log.info(message)

