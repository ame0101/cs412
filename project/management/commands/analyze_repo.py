from django.core.management.base import BaseCommand
from project.services import analyzer

class Command(BaseCommand):
    help = 'Analyzes a GitHub repository for cryptographic issues'

    def add_arguments(self, parser):
        parser.add_argument('repo_url', type=str, help='URL of the GitHub repository to analyze')

    def handle(self, *args, **options):
        repo_url = options['repo_url']
        try:
            repo = analyzer.analyze_repository(repo_url)
            self.stdout.write(self.style.SUCCESS(f'Analysis completed for repository: {repo.url}'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Error analyzing repository: {str(e)}'))