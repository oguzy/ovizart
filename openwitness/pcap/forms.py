from django import forms

class UploadPcapForm(forms.Form):
    pcap_file = forms.FileField(label="pcap file")
