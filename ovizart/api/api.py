
from tastypie.resources import ModelResource
from ovizart.pcap.models import FlowDetails
from ovizart.api.serializer import CustomJSONSerializer, AppProtocolPacketSizeCustomJSONSerializer, AppProtocolPacketCountCustomJSONSerializer, AllProtocolsJSONSerializer
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

class AppProtocolResourceByHash(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocols_by_hash'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'parent_hash_value': ALL,
            }
        serializer = CustomJSONSerializer()

class AppProtocolVisualizePacketSizeResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol_size'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'user_id': ALL,
            'protocol': ALL,
        }
        serializer = AppProtocolPacketSizeCustomJSONSerializer()

class AppProtocolVisualizePacketSizeByHashResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol_size_by_hash'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'parent_hash_value': ALL,
            'protocol': ALL,
            }
        serializer = AppProtocolPacketSizeCustomJSONSerializer()

class AppProtocolVisualizePacketCountResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol_count'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'user_id': ALL,
            'protocol': ALL,
            }
        serializer = AppProtocolPacketCountCustomJSONSerializer()

class AppProtocolVisualizePacketCountByHashResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocol_count_by_hash'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'parent_hash_value': ALL,
            'protocol': ALL,
            }
        serializer = AppProtocolPacketCountCustomJSONSerializer()

class AllProtocolsResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'all_protocols'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        serializer = AllProtocolsJSONSerializer()


class AllProtocolsByHashResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'all_protocols_by_hash'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        serializer = AllProtocolsJSONSerializer()
        filtering = {
            'parent_hash_value': ALL,
            }