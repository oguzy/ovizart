#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
import os
import hashlib

sys.path[0:0] = [
    '/home/demo/ovizart/eggs/django_tastypie-0.9.11-py2.7.egg',
    '/home/demo/ovizart/eggs/hachoir_core-1.3.3-py2.7.egg',
    '/home/demo/ovizart/eggs/hachoir_parser-1.3.4-py2.7.egg',
    '/home/demo/ovizart/eggs/hachoir_regex-1.0.5-py2.7.egg',
    '/home/demo/ovizart/eggs/hachoir_subfile-0.5.3-py2.7.egg',
    '/home/demo/ovizart/eggs/djangorecipe-1.0-py2.7.egg',
    '/home/demo/ovizart/requirements/django-nonrel',
    '/home/demo/ovizart/eggs/zc.recipe.egg-1.3.2-py2.7.egg',
    '/usr/lib/python2.7/dist-packages',
    '/home/demo/ovizart/eggs/distribute-0.6.28-py2.7.egg',
    '/home/demo/ovizart/eggs/python_dateutil-1.5-py2.7.egg',
    '/home/demo/ovizart/eggs/mimeparse-0.1.3-py2.7.egg',
    '/home/demo/ovizart/parts/django',
    '/home/demo/ovizart',
    '/home/demo/ovizart/ovizart',
    '/home/demo/ovizart/third-party/django-apps',
    ]


os.environ['DJANGO_SETTINGS_MODULE'] = 'ovizart.settings'

from django.contrib.auth.models import User
from ovizart.main.models import *

u, created = User.objects.get_or_create(username='demo')

u.set_password("ozyy4r12")
u.save()

h = hashlib.sha1()
h.update(u'demo@ovizart.foo.com')

profile, create = UserProfile.objects.get_or_create(user=u, user_email=h.hexdigest())
print "USerProfile create status: %s" % created
