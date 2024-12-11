from django.db import models
from django.utils.timezone import now
from django.contrib.auth.models import User
from django.shortcuts import redirect
from hashlib import sha256
from django.utils.http import urlsafe_base64_encode


class Repository(models.Model):
    """
    Represents a code repository.
    """
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="repositories",
        null=True,  # Allow null values for owner
        blank=True  # Allow owner to be left blank in forms
    )
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    description = models.TextField(blank=True, null=True)

    name = models.CharField(max_length=200)
    url = models.URLField(unique=True)  # Ensure URLs are unique across the database
    created_at = models.DateTimeField(auto_now_add=True)
    stars = models.IntegerField(default=0)  # Placeholder for repository star count
    last_analyzed = models.DateTimeField(auto_now=True)  # Automatically updated on save
    language = models.CharField(max_length=50, blank=True, null=True)  # Programming language
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('analyzing', 'Analyzing'),
            ('completed', 'Completed'),
            ('error', 'Error')
        ],
        default='pending',
    )
    error_message = models.TextField(blank=True)
    visibility = models.CharField(
        max_length=10,
        choices=[('public', 'Public'), ('private', 'Private')],
        default='public',
    )

    class Meta:
        unique_together = ('owner', 'name')  # Ensure that a user cannot create duplicate repositories
        ordering = ['-created_at']  # Show the latest repositories first

    def __str__(self):
        return f"{self.owner.username}/{self.name}" if self.owner else f"Unowned/{self.name}"

    @property
    def full_name(self):
        """Return the full name of the repository."""
        return f"{self.owner.username}/{self.name}" if self.owner else f"Unowned/{self.name}"

    def save(self, *args, **kwargs):
        """Override the save method to add additional validation or processing."""
        if not self.name:
            # Extract the repository name from the URL
            self.name = self.url.rstrip('/').split('/')[-1]
        super().save(*args, **kwargs)

    def toggle_visibility(self):
        """Toggle the visibility of the repository."""
        self.visibility = 'private' if self.visibility == 'public' else 'public'
        self.save()


class GitHubRepository(models.Model):
    """
    Represents a GitHub repository.
    """
    url = models.URLField(unique=True)  # Store the full GitHub repository URL
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    stars = models.IntegerField(default=0)
    language = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('analyzing', 'Analyzing'),
            ('completed', 'Completed'),
            ('error', 'Error')
        ],
        default='pending',
    )
    error_message = models.TextField(blank=True)
    visibility = models.CharField(
        max_length=10,
        choices=[('public', 'Public'), ('private', 'Private')],
        default='public',
    )
    last_analyzed = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class Comment(models.Model):
    """
    Represents a comment on a repository.
    """
    repository = models.ForeignKey(Repository, related_name="comments", on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    parent = models.ForeignKey('self', null=True, blank=True, related_name='threads', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # Track the last time the comment was updated

    def __str__(self):
        return f"Comment by {self.user.username} on {self.repository.name}"

    @property
    def is_edited(self):
        """Check if the comment has been edited."""
        return self.updated_at > self.created_at

    def can_edit_or_delete(self, user):
        """
        Check if the provided user can edit or delete this comment.
        Only the owner of the comment can perform these actions.
        """
        return self.user == user

    def edit_comment(self, new_content):
        """
        Edit the content of the comment.
        """
        self.content = new_content
        self.updated_at = now()
        self.save()

    def delete_comment(self):
        """
        Delete the comment and its associated threads.
        """
        self.delete()

    def add_thread(self, user, content):
        """
        Add a threaded reply to the comment.
        """
        return Comment.objects.create(
            repository=self.repository,
            user=user,
            content=content,
            parent=self,
        )


class CachedGitHubRepository(models.Model):
    """
    Represents a cached GitHub repository.
    """
    owner = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    html_url = models.URLField()
    open_issues_count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)  # Automatically updates every time the record is saved

    class Meta:
        ordering = ['-last_updated']  # Latest updated repositories first

    def __str__(self):
        return f"{self.owner}/{self.name}"  # Updated to display as owner/repo

    @property
    def formatted_name(self):
        """Return a base64 encoded version of owner/repo."""
        if self.owner and self.name:
            raw_name = f"{self.owner}/{self.name}"
            return urlsafe_base64_encode(raw_name.encode()) 
        return ""


class CryptoIssue(models.Model):
    """
    Represents a crypto-related issue in a repository.
    """
    repository = models.ForeignKey('Repository', on_delete=models.CASCADE, related_name='issues')
    file_path = models.CharField(max_length=255)
    line_number = models.IntegerField()
    issue_type = models.CharField(max_length=50)
    description = models.TextField()
    id = models.AutoField(primary_key=True)
    code_snippet = models.TextField(default='', blank=True)  # Ensure default blank value
    recommendation = models.TextField(default='', blank=True)  # Ensure default blank value
    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    issue_hash = models.CharField(max_length=64, unique=True, default='')
    checked_at = models.DateTimeField(null=True, blank=True)
    code_snippet = models.TextField() 

    def save(self, *args, **kwargs):
        # Generate issue hash if not set
        if not self.issue_hash:
            data = f"{self.repository_id}:{self.file_path}:{self.line_number}:{self.issue_type}"
            self.issue_hash = sha256(data.encode('utf-8')).hexdigest()

        if CryptoIssue.objects.filter(issue_hash=self.issue_hash).exists():
            return

        super().save(*args, **kwargs)  # Call the parent save method if no duplicates

    def __str__(self):
        return f"{self.repository.full_name} - {self.issue_type} at {self.file_path}:{self.line_number}"


class CVE(models.Model):
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.
    """
    nvd_issue = models.ForeignKey(CryptoIssue, on_delete=models.CASCADE)
    cve_id = models.CharField(max_length=20)
    description = models.TextField()
    published_date = models.DateField()

    def __str__(self):
        return self.cve_id


class Message(models.Model):
    """
    Represents a message associated with a repository.
    """
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    user = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.repository.name}"


class IssueReport(models.Model):
    """
    Represents an issue report for a repository.
    """
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.repository.name} - {self.title}"