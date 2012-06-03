from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField

# Create your models here.
class Flow(models.Model):
    hash_value = models.CharField(max_length=50)
    file_name = models.CharField(max_length=50)
    path = models.FilePathField()
    pcaps = ListField(EmbeddedModelField('Pcap', null=True, blank=True))
    details = ListField(EmbeddedModelField('FlowDetails', null=True, blank=True))

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

    def __unicode__(self):
        return u'(%s, %s, %s, %s, %s)' % (self.protocol, self.src_ip, self.sport, self.dst_ip, self.dport)

# save the ips at the applayerproto.log (http.log for ex)
class FlowDetails(models.Model):
    src_ip = models.IPAddressField()
    dst_ip = models.IPAddressField()
    sport = models.IntegerField()
    dport = models.IntegerField()
    protocol = models.CharField(max_length=10)
    timestamp = models.DateTimeField()


class HTTPDetails(models.Model):
    # request or response
    http_type = models.CharField(max_length=10)
    # request fields
    method = models.CharField(max_length=5, null=True, blank=True)
    uri = models.URLField(null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    version = models.FloatField(null=True, blank=True)
    # request part ends
    # response fields
    # header and version is here also
    reason = models.CharField(max_length="5", null=True, blank=True)
    status = models.IntegerField(null=True, blank=True)
    # i might need body
    body = models.TextField(null=True, blank=True)
    content_type = models.CharField(max_length=25, null=True, blank=True)
    content_encoding = models.CharField(max_length=25, null=True, blank=True)
    # response ends
    # i might need files also
    files = ListField(null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

class DNSRequest(models.Model):
    type = models.IntegerField()
    human_readable_type = models.CharField(max_length=50)
    value = models.CharField(max_length=50, null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

class DNSResponse(models.Model):
    type = models.IntegerField()
    human_readable_type = models.CharField(max_length=50)
    value = ListField(null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

class SMTPDetails(models.Model):
    login_data = ListField(null=True, blank=True)
    msg_from = models.CharField(max_length=100, null=True, blank=True)
    rcpt_to = models.CharField(max_length=100, null=True, blank=True)
    raw = models.TextField(null=True, blank=True)
    msgdata = models.TextField(null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)