from django.conf.urls.defaults import *
from pcap.views import *

urlpatterns = patterns('pcap.views',
    # upload page for pcap
    url(r'^upload/$', view='upload', name='upload_pcap'),
    )