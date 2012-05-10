from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField

# Create your models here.
class Flow(models.Model):
    hash_value = models.CharField(max_length=50)
    file_name = models.CharField(max_length=50)
    path = models.FilePathField()
    pcaps = ListField(EmbeddedModelField('Pcap', null=True, blank=True))

    def __unicode__(self):
        return u'%s/%s' % (self.path, self.file_name)

class Pcap(models.Model):
    hash_value = models.CharField(max_length=100)
    file_name = models.FileField(upload_to="uploads", null=True, blank=True)
    path = models.FilePathField()
    packets = ListField(EmbeddedModelField('PacketDetails', null=True, blank=True))

    def __unicode__(self):
        return u'%s/%s' % (self.path, self.file_name)

# there should be also a table of fields that kepts the traffic bytes related with communication

class PacketDetails(models.Model):
    #datetime.datetime.fromtimestamp(float("1286715787.71")).strftime('%Y-%m-%d %H:%M:%S')
    ident = models.IntegerField()
    timestamp = models.DateTimeField()
    protocol = models.IntegerField()
    src_ip = models.IPAddressField()
    dst_ip = models.IPAddressField()
    sport = models.IntegerField()
    dport = models.IntegerField()
    http = EmbeddedModelField('HttpDetails', null=True, blank=True)

    def __unicode__(self):
        return u'(%s, %s, %s, %s, %s)' % (self.protocol, self.src_ip, self.sport, self.dst_ip, self.dport)

class HttpDetails(models.Model):
    # request or response
    http_type = models.CharField(max_length=10)
    # request fields
    method = models.CharField(max_length=5, null=True, blank=True)
    uri = models.URLField(null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    version = models.FloatField(null=True, blank=True)
    # request part ends
    # responde fields
    # header and version is here also
    reason = models.CharField(max_length="5", null=True, blank=True)
    status = models.IntegerField(null=True, blank=True)
    body = models.TextField(null=True, blank=True)
    # response ends
    files = ListField(null=True, blank=True)
