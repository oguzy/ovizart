#!/usr/bin/env python
#-*- coding: UTF-8 -*-

import sys
import os
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../..')))
sys.path[0:0] = [
    '/home/oguz/git/openwitness/eggs/django_tastypie-0.9.11-py2.7.egg',
    '/usr/lib/pymodules/python2.7',
    '/usr/lib/pymodules/python2.7',
    '/usr/lib/pymodules/python2.7',
    '/home/oguz/git/openwitness/eggs/hachoir_regex-1.0.5-py2.7.egg',
    '/home/oguz/git/openwitness/eggs/djangorecipe-1.0-py2.7.egg',
    '/home/oguz/git/openwitness/requirements/django-nonrel',
    '/home/oguz/git/openwitness/eggs/zc.recipe.egg-1.3.2-py2.7.egg',
    '/usr/lib/python2.7/dist-packages',
    '/usr/lib/python2.7/dist-packages',
    '/home/oguz/git/openwitness/eggs/distribute-0.6.27-py2.7.egg',
    '/home/oguz/git/openwitness/eggs/mimeparse-0.1.3-py2.7.egg',
    '/home/oguz/git/openwitness/parts/django',
    '/home/oguz/git/openwitness',
    '/home/oguz/git/openwitness/openwitness',
    '/home/oguz/git/openwitness/third-party/django-apps',
    ]
os.environ['DJANGO_SETTINGS_MODULE'] = 'openwitness.settings'

from django.contrib.auth.models import User
from main.models import *

u, created = User.objects.get_or_create(username='some_user_name_here')

u.set_password("some_password_here")
u.save()

hashlib.sha1()
h = hashlib.sha1()
h.update("some_email_here")

profile, create = UserProfile.objects.get_or_create(user=u, user_email=h.hexdigest())
