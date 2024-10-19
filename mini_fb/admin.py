from django.contrib import admin
from .models import Profile, StatusMessage, Image

admin.site.register(Profile)
admin.site.register(StatusMessage)
admin.site.register(Image)