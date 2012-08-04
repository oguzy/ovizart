from django.conf.urls.defaults import *
from openwitness.pcap.views import *

urlpatterns = patterns('',
    # upload page for pcap
    url(r'^upload/', view=upload, name='upload_pcap'),
    url(r'^(?P<flow_pcap_md5>\w+)/$', view=flow_pcap_details, name='flow_pcap_details'),
    url(r'^summary/$', view=summary, name='summary_pcap'),
    url(r'^summary/(?P<hash_value>\w+)/$', view=file_pcap_summary, name='file_pcap_summary'),
    url(r'^visualize/(?P<protocol>\w+)/(?P<type>\w+)/$', view=visualize, name='visualize_app_layer'),
    url(r'^flow/(?P<flow_id>\w+)/$', view=flow_details, name='flow_details'),
    url(r'^get_pcap_url/(?P<id>\w+)/$', view=get_pcap_url, name='get_pcap_url'),
    url(r'^info/(?P<packet_ident>\w+)/$', view=get_packet_info, name='packet_info'),
    url(r'^(?P<hash_value>\w+)/(?P<protocol>\w+)/(?P<date>\w+)$', view=file_protocol_summary, name='file_protocol_summary'),

    )