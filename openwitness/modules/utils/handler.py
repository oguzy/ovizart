#!/usr/bin/env python
#-*- coding: UTF-8 -*-


import random
import string
import time
import hashlib


def generate_random_name(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(N))

def generate_name_from_timestame():
    timestamp = str(time.time())
    md5 = hashlib.md5(timestamp)
    return md5.hexdigest()
