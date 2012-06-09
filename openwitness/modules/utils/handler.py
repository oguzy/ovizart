#!/usr/bin/env python
#-*- coding: UTF-8 -*-


import random
import string
import time
import hashlib
import datetime
import math

MIN_DT = "1970-01-01 00:00:00"
MAX_DT = "2038-01-01 00:00:00"
MIN_TS = int(datetime.datetime.strptime(MIN_DT, "%Y-%m-%d %H:%M:%S").strftime("%s"))
MAX_TS = int(datetime.datetime.strptime(MAX_DT, "%Y-%m-%d %H:%M:%S").strftime("%s"))

def generate_random_name(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(N))

def generate_name_from_timestame():
    timestamp = str(time.time())
    md5 = hashlib.md5(timestamp)
    return md5.hexdigest()

# find a importance value by looking at the end timestamp
def translate_time(value, leftMin=MIN_TS, leftMax=MAX_TS, rightMin=1, rightMax=100):
    # Figure out how 'wide' each range is
    leftSpan = leftMax - leftMin
    rightSpan = rightMax - rightMin

    # Convert the left range into a 0-1 range (float)
    valueScaled = float(value - leftMin) / float(leftSpan)

    # Convert the range into a value in the right range.
    return int(math.floor(rightMin + (valueScaled * rightSpan)))
