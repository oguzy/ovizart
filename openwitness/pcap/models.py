from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField

# Create your models here.

class Pcap(models.Model):
    name = models.FileField(upload_to="uploads", null=True, blank=True)
    path = models.FilePathField()
    information = EmbeddedModelField('PacketDetails', null=True, blank=True)

class PacketDetails(models.Model):
    protocol = models.CharField(max_length=10)
    source_ip = models.IPAddressField()
    destionation_ip = models.IPAddressField()
    source_port = models.IntegerField()
    destionation_port = models.IntegerField()
    files = ListField(null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    body = models.TextField(null=True, blank=True)
