from django.db import models

class Profile(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    email_address = models.EmailField(max_length=200)
    profile_image_url = models.URLField(max_length=200)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"