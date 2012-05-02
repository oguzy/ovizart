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
    timestamp = models.DateTimeField()
    protocol = models.CharField(max_length=10)
    source_ip = models.IPAddressField()
    destionation_ip = models.IPAddressField()
    source_port = models.IntegerField()
    destionation_port = models.IntegerField()
    files = ListField(null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    body = models.TextField(null=True, blank=True)
