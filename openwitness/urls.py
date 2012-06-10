
from django.conf.urls.defaults import *
from django.conf import settings
from openwitness.api.api import AppProtocolResource

app_protocol_resource = AppProtocolResource()

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^{{ project_name }}/', include('{{ project_name }}.foo.urls')),
    url(r'^$', 'openwitness.main.views.login_user', name='login_page'),
    url(r'^logout/', 'openwitness.main.views.logout_user', name='logout_page'),
    (r'^pcap/', include('openwitness.pcap.urls')),
    (r'^api/', include(app_protocol_resource.urls)),

    # Uncomment the admin/doc line below to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    (r'^admin/', include(admin.site.urls)),
)


if settings.DEBUG:
    urlpatterns += patterns('',
        (r'^site_media/(?P<path>.*)$', 'django.views.static.serve',
             {'document_root': settings.MEDIA_ROOT, 'show_indexes': True}),
        (r'^json_media/(?P<path>.*)$', 'django.views.static.serve',
             {'document_root': settings.JSON_ROOT, 'show_indexes': True})
    )

