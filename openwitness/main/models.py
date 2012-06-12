from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User)
    user_email = models.CharField(max_length=100) # sha1 hash value of the email
