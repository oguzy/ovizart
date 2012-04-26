from django import forms

class UploadPcapForm(forms.Form):
    file = forms.FileInput()
