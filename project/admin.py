"""
admin.py - Register models with the Django admin site.
"""

from django.contrib import admin
from .models import Repository, CryptoIssue, CVE, Message, IssueReport

admin.site.register(Repository)
admin.site.register(CryptoIssue) 
admin.site.register(CVE)
admin.site.register(Message)
admin.site.register(IssueReport)