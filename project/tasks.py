from django.conf import settings
from .services import GitHubService

def sync_github_issues():
    service = GitHubService(settings.GITHUB_TOKEN)
    service.sync_issues()