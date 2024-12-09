import re
from django import forms
from .models import Message, IssueReport, Repository
from django.contrib.auth.models import User
from .models import Repository
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['user', 'content']

class IssueReportForm(forms.ModelForm):
    class Meta:
        model = IssueReport
        fields = ['title', 'description', 'status']

class RepositoryForm(forms.Form):
    repository_url = forms.URLField(
        label="GitHub Repository URL",
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'https://github.com/owner/repository'
        }),
        validators=[URLValidator()]
    )

    def clean_repository_url(self):
        url = self.cleaned_data['repository_url']
        if not re.match(r'^https://github\.com/[^/]+/[^/]+/?$', url):
            raise ValidationError("Enter a valid GitHub repository URL.")
        return url


class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email']

    def clean_password_confirm(self):
        password = self.cleaned_data.get('password')
        password_confirm = self.cleaned_data.get('password_confirm')

        if password != password_confirm:
            raise forms.ValidationError("Passwords do not match")

        return password_confirm

class LoginForm(forms.Form):
    username = forms.CharField(max_length=100)
    password = forms.CharField(widget=forms.PasswordInput)


class RepositoryAnalysisForm(forms.ModelForm):
    class Meta:
        model = Repository
        fields = ['name', 'url', 'visibility'] 
