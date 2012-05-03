from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField

# Create your models here.
class Flow(models.Model):
    file_name = models.CharField(max_length=100)
    path = models.FilePathField()
    pcaps = ListField(EmbeddedModelField('Pcap', null=True, blank=True))

class Pcap(models.Model):
    file_name = models.FileField(upload_to="uploads", null=True, blank=True)
    path = models.FilePathField()
    packets = EmbeddedModelField('PacketDetails', null=True, blank=True)

class PacketDetails(models.Model):
    #datetime.datetime.fromtimestamp(float("1286715787.71")).strftime('%Y-%m-%d %H:%M:%S')
    timestamp = models.DateTimeField()
    protocol = models.CharField(max_length=10)
    source_ip = models.IPAddressField()
    destionation_ip = models.IPAddressField()
    source_port = models.IntegerField()
    destionation_port = models.IntegerField()
    http = EmbeddedModelField('HttpDetails', null=True, blank=True)

class HttpDetails(models.Model):
    # request or response
    http_type = models.CharField(max_length=10)
    # request fields
    method = models.CharField(max_length=5)
    uri = models.URLField()
    headers = models.TextField()
    version = models.IntegerField()
    # request part ends
    # responde fields
    # header and version is here also
    reason = models.CharField(max_length="5")
    status = models.IntegerField()
    body = models.TextField()
    # response ends
    files = ListField(null=True, blank=True)
