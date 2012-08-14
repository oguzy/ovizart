#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
import os
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../..')))
sys.path[0:0] = [
    '/home/oguz/git/ovizart/eggs/django_tastypie-0.9.11-py2.7.egg',
    '/usr/lib/pymodules/python2.7',
    '/usr/lib/pymodules/python2.7',
    '/usr/lib/pymodules/python2.7',
    '/home/oguz/git/ovizart/eggs/hachoir_regex-1.0.5-py2.7.egg',
    '/home/oguz/git/ovizart/eggs/djangorecipe-1.0-py2.7.egg',
    '/home/oguz/git/ovizart/requirements/django-nonrel',
    '/home/oguz/git/ovizart/eggs/zc.recipe.egg-1.3.2-py2.7.egg',
    '/usr/lib/python2.7/dist-packages',
    '/usr/lib/python2.7/dist-packages',
    '/home/oguz/git/ovizart/eggs/distribute-0.6.27-py2.7.egg',
    '/home/oguz/git/ovizart/eggs/mimeparse-0.1.3-py2.7.egg',
    '/home/oguz/git/ovizart/parts/django',
    '/home/oguz/git/ovizart',
    '/home/oguz/git/ovizart/ovizart',
    '/home/oguz/git/ovizart/third-party/django-apps',
    ]
os.environ['DJANGO_SETTINGS_MODULE'] = 'ovizart.settings'

from django.contrib.auth.models import User
from main.models import *

u, created = User.objects.get_or_create(username='demo')

u.set_password("ozyy4r12")
u.save()

h = hashlib.sha1()
h.update(u'demo@ovizart.foo.com')

profile, create = UserProfile.objects.get_or_create(user=u, user_email=h.hexdigest())
print "USerProfile create status: %s" % created
