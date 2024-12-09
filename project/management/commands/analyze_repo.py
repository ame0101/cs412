from django.core.management.base import BaseCommand
from project.services import analyzer
import subprocess

class Command(BaseCommand):
    help = 'Analyzes a GitHub repository for cryptographic issues'

    def add_arguments(self, parser):
        parser.add_argument('repo_url', type=str, help='URL of the GitHub repository to analyze')

         
    def handle(self, *args, **options):
        repo_url = options['repo_url']
        try:
            # Verify CodeQL installation
            subprocess.run(['codeql', '--version'], 
                        check=True, capture_output=True)
            
            repo = analyzer.analyze_repository(repo_url)
            self.stdout.write(
                self.style.SUCCESS(f'Analysis completed for repository: {repo.url}')
            )
        except subprocess.CalledProcessError as e:
            self.stderr.write(
                self.style.ERROR(f'CodeQL verification failed: {e.stderr}')
            )
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f'Error analyzing repository: {str(e)}')
            )