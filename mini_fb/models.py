from django import forms
from django.db import models
from django.urls import reverse
from django.utils import timezone

class Profile(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    profile_image_url = models.URLField(max_length=200)
    email_address = models.EmailField(null=True, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    

    def get_absolute_url(self):
        return reverse('show_profile', kwargs={'pk': self.pk})
    


class Image(models.Model):
    image_file = models.ImageField(upload_to='images/')
    status_message = models.ForeignKey('StatusMessage', on_delete=models.CASCADE, related_name='images')
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Image for {self.status_message} uploaded at {self.timestamp}"



class StatusMessage(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.profile.first_name} {self.profile.last_name}: {self.message[:20]}..."
    
    def get_images(self):
        return self.images.all()