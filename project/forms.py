from django import forms
from .models import Message, IssueReport

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
        label='GitHub Repository URL',
        help_text='e.g., https://github.com/owner/repository',
        widget=forms.URLInput(attrs={
            'class': 'w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500',
            'placeholder': 'https://github.com/owner/repository'
        })
    )

    def clean_repository_url(self):
        url = self.cleaned_data['repository_url']
        if 'github.com' not in url:
            raise forms.ValidationError('Please enter a valid GitHub repository URL')
        return url
    
