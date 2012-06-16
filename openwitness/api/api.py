
from tastypie.resources import ModelResource
from openwitness.pcap.models import FlowDetails
from openwitness.api.serializer import CustomJSONSerializer, AppProtocolPacketSizeCustomJSONSerializer, AppProtocolPacketCountCustomJSONSerializer
from tastypie.constants import ALL

class AppProtocolResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocols'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'user_id': ALL,
        }
        serializer = CustomJSONSerializer()

class AppProtocolVisualizePacketSizeResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'user_id': ALL,
            'protocol': ALL,
        }
        serializer = AppProtocolPacketSizeCustomJSONSerializer()

class AppProtocolVisualizePacketCountResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'user_id': ALL,
            'protocol': ALL,
            }
        serializer = AppProtocolPacketCountCustomJSONSerializer()



