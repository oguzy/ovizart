from django.forms import ModelForm
from django import forms
from main.models import UserProfile
from django.contrib.auth.models import User
import hashlib


class LoginForm(ModelForm):
    user_email = forms.EmailField()
    class Meta:
        model = User
        fields = ('username', 'user_email', 'password')

    def clean(self):
        data = self.cleaned_data
        email = data.get('user_email')
        if not email:
            raise forms.ValidationError(u'Email can not be empty!')
        hash = hashlib.sha1()
        hash.update(email)
        email_hash = hash.hexdigest()
        username = self.cleaned_data.get('username')
        if not username:
            raise forms.ValidationError(u'Username can not be empty!')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError(u'User does not exist.')
        if email and UserProfile.objects.filter(user_email=email_hash, user=user).count():
            return data
        else:
            raise forms.ValidationError(u'Profile for the user does not exist')
