
from django.conf.urls.defaults import *
from django.conf import settings
from tastypie.api import Api
from openwitness.api.api import AppProtocolResource, AppProtocolVisualizePacketSizeResource, \
                                AppProtocolVisualizePacketCountResource, AllProtocolsResource, \
                                AllProtocolsByHashResource, AppProtocolResourceByHash, \
                                AppProtocolVisualizePacketSizeByHashResource, \
                                AppProtocolVisualizePacketCountByHashResource


rest_api = Api(api_name='rest')
rest_api.register(AppProtocolResource())
rest_api.register(AppProtocolVisualizePacketSizeResource())
rest_api.register(AppProtocolVisualizePacketCountResource())
rest_api.register(AllProtocolsResource())
rest_api.register(AllProtocolsByHashResource())
rest_api.register(AppProtocolResourceByHash())
rest_api.register(AppProtocolVisualizePacketSizeByHashResource())
rest_api.register(AppProtocolVisualizePacketCountByHashResource())

#app_protocol_resource = AppProtocolResource()
#app_protocol_size_resource = AppProtocolVisualizePacketSizeResource()
#app_protocol_count_resource = AppProtocolVisualizePacketCountResource()

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^{{ project_name }}/', include('{{ project_name }}.foo.urls')),
    #url(r'^$', 'openwitness.main.views.login_user', name='login_page'),
    url(r'^$', 'openwitness.main.views.main', name='main_page'),
    url(r'^login/', 'openwitness.main.views.login_user', name='login_page'),
    url(r'^logout/', 'openwitness.main.views.logout_user', name='logout_page'),
    (r'^pcap/', include('openwitness.pcap.urls')),
    (r'^main/', include('openwitness.main.urls')),
    (r'^api/', include(rest_api.urls)),


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
             {'document_root': settings.JSON_ROOT, 'show_indexes': True}),
        (r'^uploads/(?P<path>.*)$', 'django.views.static.serve',
             {'document_root': settings.UPLOAD_ROOT, 'show_indexes': True}),
    )

