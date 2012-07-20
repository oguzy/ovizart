from django.conf.urls.defaults import *
from openwitness.pcap.views import *

urlpatterns = patterns('',
    # upload page for pcap
    url(r'^upload/', view=upload, name='upload_pcap'),
    url(r'^summary/', view=summary, name='summary_pcap'),
    url(r'^visualize/(?P<protocol>\w+)/(?P<type>\w+)/$', view=visualize, name='visualize_app_layer'),
    url(r'^flow/(?P<flow_id>\w+)/$', view=flow_details, name='flow_details'),
    url(r'^get_pcap_url/(?P<id>\w+)/$', view=get_pcap_url, name='get_pcap_url'),
    )