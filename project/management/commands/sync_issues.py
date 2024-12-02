from django.core.management.base import BaseCommand
from django.conf import settings
from project.services import GitHubService

class Command(BaseCommand):
    help = 'Syncs crypto issues from GitHub'

    def handle(self, *args, **options):
        try:
            token = settings.GITHUB_TOKEN
            if not token:
                self.stderr.write(self.style.ERROR('GitHub token not found. Please set GITHUB_TOKEN in your .env file'))
                return
                
            service = GitHubService(token)
            service.sync_issues()
            self.stdout.write(self.style.SUCCESS('Successfully synced issues'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Error syncing issues: {str(e)}'))