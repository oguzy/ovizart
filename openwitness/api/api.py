
from tastypie.resources import ModelResource
from openwitness.pcap.models import FlowDetails
from openwitness.api.serializer import CustomJSONSerializer
from tastypie.constants import ALL

class AppProtocolResource(ModelResource):
    class Meta:
        queryset = FlowDetails.objects.all()
        resource_name = 'protocols'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        limit = 0 # unlimited
        filtering = {
            'session_key': ALL,
        }
        serializer = CustomJSONSerializer()


