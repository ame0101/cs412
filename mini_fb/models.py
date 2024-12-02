from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User  # Import the User model

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    email_address = models.EmailField(max_length=50)
    profile_image_url = models.URLField(max_length=200)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def get_absolute_url(self):
        return reverse('show_profile', kwargs={'pk': self.pk})

    def get_friends(self):
        friends1 = Friend.objects.filter(profile1=self).select_related('profile2')
        friends2 = Friend.objects.filter(profile2=self).select_related('profile1')
        friends = [friend.profile2 for friend in friends1] + [friend.profile1 for friend in friends2]
        return friends

    def add_friend(self, other):
        if self == other:
            raise ValidationError("You cannot add yourself as a friend.")
        existing_friend = Friend.objects.filter(profile1=self, profile2=other).exists() or \
                          Friend.objects.filter(profile1=other, profile2=self).exists()
        if not existing_friend:
            Friend.objects.create(profile1=self, profile2=other)
        else:
            raise ValidationError("This friendship already exists.")

    def get_friend_suggestions(self):
        current_friends = self.get_friends()
        current_friend_ids = [friend.id for friend in current_friends]
        suggestions = Profile.objects.exclude(id=self.id).exclude(id__in=current_friend_ids)
        return suggestions

    def get_news_feed(self):
        friends = self.get_friends()
        own_messages = StatusMessage.objects.filter(profile=self)
        friends_messages = StatusMessage.objects.filter(profile__in=friends)
        news_feed = own_messages | friends_messages
        return news_feed.order_by('-timestamp')

class Friend(models.Model):
    profile1 = models.ForeignKey(Profile, related_name='friends1', on_delete=models.CASCADE)
    profile2 = models.ForeignKey(Profile, related_name='friends2', on_delete=models.CASCADE)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.profile1} & {self.profile2}"

    class Meta:
        unique_together = ('profile1', 'profile2')

class StatusMessage(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.profile.first_name} {self.profile.last_name}: {self.message[:20]}..."

    def get_images(self):
        return self.images.all()

class Image(models.Model):
    image_file = models.ImageField(upload_to='images/')
    status_message = models.ForeignKey('StatusMessage', on_delete=models.CASCADE, related_name='images')
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Image for {self.status_message} uploaded at {self.timestamp}"
