from django.db import models
from django.utils.timezone import now


class Repository(models.Model):
    name = models.CharField(max_length=200)
    owner = models.CharField(max_length=255, default="Unknown Owner")  # Default value added
    url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)
    stars = models.IntegerField(default=0)
    last_analyzed = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('analyzing', 'Analyzing'),
        ('completed', 'Completed'),
        ('error', 'Error')
    ], default='pending')
    error_message = models.TextField(blank=True)

    def __str__(self):
        return f"{self.owner}/{self.name}"

    @property
    def full_name(self):
        return f"{self.owner}/{self.name}"
class CryptoIssue(models.Model):
    repository = models.ForeignKey('Repository', on_delete=models.CASCADE, related_name='issues')
    file_path = models.CharField(max_length=255)
    line_number = models.IntegerField()
    issue_type = models.CharField(max_length=50)
    description = models.TextField()

    code_snippet = models.TextField(null=True, blank=True)
    recommendation = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)
    checked_at = models.DateTimeField(null=True, blank=True)  # Add this field

    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ])
    created_at = models.DateTimeField(auto_now_add=True)
    code_snippet = models.TextField()
    recommendation = models.TextField()

    def __str__(self):
        return f"{self.repository.full_name} - {self.issue_type} at {self.file_path}:{self.line_number}"
    
class CVE(models.Model):
    nvd_issue = models.ForeignKey(CryptoIssue, on_delete=models.CASCADE)
    cve_id = models.CharField(max_length=20)
    description = models.TextField()
    published_date = models.DateField()

    def __str__(self):
        return self.cve_id

class Message(models.Model):
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    user = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.repository.name}"

class IssueReport(models.Model):
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.repository.name} - {self.title}"
    

