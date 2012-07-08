from django.conf.urls.defaults import *
from openwitness.main.views import *

urlpatterns = patterns('',
    url(r'^(?P<protocol>\w+)/(?P<date>\w+)$', view=flow_protocol_summary, name='flow_protocol_summary'),
    )