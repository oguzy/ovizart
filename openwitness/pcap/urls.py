from django.conf.urls.defaults import *
from openwitness.pcap.views import *

urlpatterns = patterns('',
    # upload page for pcap
    url(r'^upload/', view=upload, name='upload_pcap'),
    )