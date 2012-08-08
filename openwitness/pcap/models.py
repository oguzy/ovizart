from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField
from django_mongodb_engine.contrib import MongoDBManager
import os

# Create your models here.
# save the created json file name path
# only one file for summary should be kept here
class UserJSonFile(models.Model):
    user_id = models.CharField(max_length=100)
    json_type = models.CharField(max_length=10) # possible value is summary for the summary view
    json_file_name = models.CharField(max_length=100) # save the name of the already created file name on disk

class Flow(models.Model):
    user_id = models.CharField(max_length=100)
    hash_value = models.CharField(max_length=50)
    file_name = models.CharField(max_length=50)
    upload_time = models.DateTimeField()
    file_type = models.CharField(max_length=150)
    file_size = models.IntegerField()
    path = models.FilePathField()
    pcaps = ListField(EmbeddedModelField('Pcap', null=True, blank=True))
    details = ListField(EmbeddedModelField('FlowDetails', null=True, blank=True))

    def __unicode__(self):
        return u'%s/%s' % (self.path, self.file_name)

    def get_upload_path(self):
        hash_dir = os.path.basename(self.path)
        root = os.path.basename(os.path.dirname(self.path))
        return os.path.join(root, hash_dir)

class Pcap(models.Model):
    hash_value = models.CharField(max_length=100)
    file_name = models.FileField(upload_to="uploads", null=True, blank=True)
    path = models.FilePathField()
    packets = ListField(EmbeddedModelField('PacketDetails', null=True, blank=True))

    def __unicode__(self):
        return u'%s/%s' % (self.path, self.file_name)

    def get_upload_path(self):
        hash_dir = os.path.basename(self.path)
        root = os.path.basename(os.path.dirname(self.path))
        return os.path.join(root, hash_dir)

# there should be also a table of fields that kepts the traffic bytes related with communication

class PacketDetails(models.Model):
    #datetime.datetime.fromtimestamp(float("1286715787.71")).strftime('%Y-%m-%d %H:%M:%S')
    ident = models.IntegerField()
    flow_hash = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    length = models.IntegerField()
    protocol = models.IntegerField()
    src_ip = models.IPAddressField()
    dst_ip = models.IPAddressField()
    sport = models.IntegerField()
    dport = models.IntegerField()
    data = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u'(%s, %s, %s, %s, %s)' % (self.protocol, self.src_ip, self.sport, self.dst_ip, self.dport)

    objects = MongoDBManager()

# save the ips at the applayerproto.log (http.log for ex)
class FlowDetails(models.Model):
    parent_hash_value = models.CharField(max_length=50)
    user_id = models.CharField(max_length=100)
    src_ip = models.IPAddressField()
    dst_ip = models.IPAddressField()
    sport = models.IntegerField()
    dport = models.IntegerField()
    protocol = models.CharField(max_length=10)
    timestamp = models.DateTimeField()

    objects = MongoDBManager()


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
    file_path = models.CharField(max_length=200, null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

    #for raw_qeuries, filtering according to flow_details will be possible
    objects = MongoDBManager()


class DNSRequest(models.Model):
    type = models.IntegerField()
    human_readable_type = models.CharField(max_length=50)
    value = models.CharField(max_length=50, null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

    objects = MongoDBManager()

class DNSResponse(models.Model):
    type = models.IntegerField()
    human_readable_type = models.CharField(max_length=50)
    value = ListField(null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

    objects = MongoDBManager()

class SMTPDetails(models.Model):
    login_data = ListField(null=True, blank=True)
    msg_from = models.CharField(max_length=100, null=True, blank=True)
    rcpt_to = models.CharField(max_length=100, null=True, blank=True)
    raw = models.TextField(null=True, blank=True)
    msgdata = models.TextField(null=True, blank=True)
    attachment_path = ListField(null=True, blank=True)
    flow_details = EmbeddedModelField('FlowDetails', null=True, blank=True)

    objects = MongoDBManager()

    def get_path_dict(self):
        #/home/oguz/git/openwitness/openwitness/uploads/16-06-12/a6a6defb7253043a55281d01aa66538a/smtp-messages/1/part-001.ksh
        result = []
        for path in self.attachment_path:
            tmp = dict()
            r = path.split("uploads")
            file_name = os.path.basename(r[1])
            tmp['file_name'] = file_name
            tmp['path'] = r[1]
            result.append(tmp)

        return result