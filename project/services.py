# Standard library imports
import re
import base64
import hashlib
import json
import ast
from datetime import datetime
import requests
import asyncio
from asgiref.sync import sync_to_async
from django.utils.timezone import now
from django.conf import settings
from django.db import IntegrityError
from django.core.cache import cache
from .models import Repository, CryptoIssue, GitHubRepository
import logging

logger = logging.getLogger(__name__)

class CryptoAnalyzer:
    def __init__(self, github_token, user=None):
        self.token = github_token
        self.user = user
        self.headers = {'Authorization': f'token {github_token}'}
        self.session = requests.Session()
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

    def analyze_repository(self, repo_url):
        logger.info(f"Starting analysis for repository: {repo_url}")
        repo = None  # Initialize repo to None

        try:
            # Owner and name from the URL
            match = re.match(r'https://github.com/([^/]+)/([^/]+)', repo_url)
            if not match:
                raise ValueError("Invalid xGitHub repository URL format.")

            owner, name = match.groups()

            # Fetch repo details from GitHub
            repo_details_url = f'https://api.github.com/repos/{owner}/{name}'
            response = self.session.get(repo_details_url, headers=self.headers)
            repo_details = response.json()

            if response.status_code == 404:
                raise ValueError("The GitHub repository was not found.")
            elif response.status_code != 200:
                raise ValueError(f"Failed to fetch repository details: {repo_details.get('message', 'Unknown error')}")

            # Check if repository is empty
            if repo_details.get('size', 0) == 0:
                raise ValueError("The repository is empty and cannot be analyzed.")

            # Get or create the repository
            repo, created = Repository.objects.get_or_create(
                url=repo_url,
                defaults={
                    'name': name,
                    'owner': self.user,  # Associate with the current user
                    'language': repo_details.get('language', 'Unknown'),
                }
            )

            if not created:
                # If the repository already exists, update its owner to include the current user
                logger.info(f"Repository already exists: {repo.full_name}")
                if repo.owner != self.user:
                    repo.owner = self.user
                    repo.save()
                return repo

            # Update repo status
            repo.status = 'analyzing'
            repo.save()

            # Start analysis
            contents_url = f'https://api.github.com/repos/{owner}/{name}/contents'
            asyncio.run(self.analyze_contents_async(repo, contents_url))

            # After analysis is complete, update the status
            repo.status = 'completed'
            repo.save()
            logger.info(f"Analysis completed for repository: {repo_url}")
            return repo

        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error analyzing repository {repo_url}: {str(e)}", exc_info=True)
            if repo:
                repo.status = 'error'
                repo.error_message = str(e)
                repo.save()
            raise

    async def analyze_contents_async(self, repo, contents_url, path_prefix=''):
        """Analyze the contents of a repository asynchronously."""
        logger.info(f"Fetching contents from: {contents_url}")
        try:
            async with self.semaphore:
                response = self.session.get(contents_url, headers=self.headers)
                response.raise_for_status()
                contents = response.json()

                if not isinstance(contents, list):
                    contents = [contents]

                tasks = []
                for item in contents:
                    item_path = f"{path_prefix}/{item['name']}" if path_prefix else item['name']

                    if item['type'] == 'file':
                        if self._is_analyzable_file(item['name']):
                            # Skip already analyzed files
                            if cache.get(item_path):
                                logger.info(f"Skipping cached file: {item_path}")
                                continue
                            logger.info(f"Scheduling analysis for file: {item_path}")
                            tasks.append(self.analyze_file_async(repo, item, item_path))
                    elif item['type'] == 'dir':
                        logger.info(f"Found directory: {item_path}")
                        tasks.append(self.analyze_contents_async(repo, item['url'], item_path))

                if tasks:
                    await asyncio.gather(*tasks)

        except Exception as e:
            logger.error(f"Error analyzing contents at {contents_url}: {e}", exc_info=True)

    async def analyze_file_async(self, repo, file_info, file_path):
        retries = 3
        for attempt in range(retries):
            try:
                response = self.session.get(file_info['url'], headers=self.headers)
                response.raise_for_status()
                content = response.json()

                if content['encoding'] == 'base64':
                    file_content = base64.b64decode(content['content']).decode('utf-8')

                    if file_path.endswith('.py'):
                        await self._analyze_python_content(repo, file_path, file_content)
                    elif file_path.endswith('.go'):
                        self._analyze_go_content(repo, file_path, file_content)
                    else:
                        logger.info(f"Skipping unsupported file type: {file_path}")

                    # Cache the file as analyzed
                    cache.set(file_path, True, timeout=60 * 60 * 24 * 7)  # Cache for a week
                return
            except Exception as e:
                if attempt < retries - 1:
                    logger.warning(f"Retrying file analysis for {file_path}: {e}")
                    await asyncio.sleep(2 ** attempt)
                else:
                    logger.error(f"Failed to analyze file {file_path} after {retries} attempts.", exc_info=True)

    async def _analyze_python_content(self, repo, file_path, content):
        try:
            logger.info(f"Analyzing Python content for file: {file_path}")
            tree = ast.parse(content)
            await self._analyze_content(repo, file_path, content)
        except SyntaxError as e:
            logger.error(f"Syntax error in Python file {file_path}: {str(e)}", exc_info=True)

    def _analyze_go_content(self, repo, file_path, content):
        logger.info(f"Analyzing Go content for file: {file_path}")
        # Stub for Go analysis logic

    def _is_analyzable_file(self, filename):
        extensions = (
            '.py', '.js', '.java', '.go', '.rb', '.php',
            '.cpp', '.c', '.h', '.cs', '.ts', '.swift',
            '.m', '.scala', '.rs', '.kt'
        )
        return filename.lower().endswith(extensions)
 
 
    async def _analyze_content(self, repo, file_path, content):
        try:
            issues = []
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ['DES', 'MD5']:
                        issue = await self._create_issue(repo, file_path, node, 'weak_cipher', 'Weak or deprecated cryptographic algorithm detected')
                        if issue:
                            issues.append(issue)
                    elif node.func.id in ['random', 'Math.random', 'rand', 'srand']:
                        issue = await self._create_issue(repo, file_path, node, 'unsafe_random', 'Potentially unsafe random number generation')
                        if issue:
                            issues.append(issue)
                    elif node.func.id == 'ECB':
                        issue = await self._create_issue(repo, file_path, node, 'insecure_mode', 'Insecure mode of operation (ECB) detected')
                        if issue:
                            issues.append(issue)
                    elif node.func.id == 'eval':
                        issue = await self._create_issue(repo, file_path, node, 'code_injection', 'Potential code injection vulnerability detected')
                        if issue:
                            issues.append(issue)
                    elif node.func.id == 'exec':
                        issue = await self._create_issue(repo, file_path, node, 'command_injection', 'Potential command injection vulnerability detected')
                        if issue:
                            issues.append(issue)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.lower() in ['password', 'secret', 'key', 'token', 'credential']:
                            issue = await self._create_issue(repo, file_path, node, 'hardcoded_secret', 'Potential hardcoded secret detected')
                            if issue:
                                issues.append(issue)
                elif isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name.lower() in ['cryptography', 'pycrypto', 'pynacl', 'passlib']:
                            issue = await self._create_issue(repo, file_path, node, 'insecure_library', 'Potentially insecure cryptography library detected')
                            if issue:
                                issues.append(issue)
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'ssl':
                    if node.attr in ['CERT_NONE', 'CERT_OPTIONAL']:
                        issue = await self._create_issue(repo, file_path, node, 'insecure_ssl', 'Insecure SSL/TLS certificate verification detected')
                        if issue:
                            issues.append(issue)
                elif isinstance(node, ast.Str):
                    if re.search(r'\b(password|secret|key|token|credential)\b', node.s, re.IGNORECASE):
                        issue = await self._create_issue(repo, file_path, node, 'sensitive_data', 'Potential sensitive data in string literal detected')
                        if issue:
                            issues.append(issue)
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift):
                    issue = await self._create_issue(repo, file_path, node, 'weak_hash', 'Potentially weak custom hash function detected')
                    if issue:
                        issues.append(issue)

            if issues:
                # Now using sync_to_async for database operations
                await self._handle_issues_bulk(issues)

        except Exception as e:
            logger.error(f"Error analyzing content for {file_path}: {str(e)}", exc_info=True)

    # Wrap the ORM method to run in an async context
    @sync_to_async
    def _handle_issues_bulk(self, issues):
        existing_hashes = set(CryptoIssue.objects.filter(issue_hash__in=[i.issue_hash for i in issues]).values_list('issue_hash', flat=True))
        new_issues = [i for i in issues if i.issue_hash not in existing_hashes]

        if new_issues:
            try:
                CryptoIssue.objects.bulk_create(new_issues)
            except IntegrityError as e:
                logger.error(f"IntegrityError during bulk create: {str(e)}", exc_info=True)
    @sync_to_async
    def _handle_issues(self, issues):
        for issue in issues:
            try:
                # Use get_or_create to make sure it's a new issue
                existing_issue, created = CryptoIssue.objects.get_or_create(
                    issue_hash=issue.issue_hash,
                    defaults={
                        'repository': issue.repository,
                        'file_path': issue.file_path,
                        'line_number': issue.line_number,
                        'issue_type': issue.issue_type,
                        'description': issue.description,
                        'code_snippet': issue.code_snippet,
                        'recommendation': issue.recommendation,
                        'severity': issue.severity,
                    }
                )
                if not created:
                    # Update the existing issue if needed
                    existing_issue.checked_at = datetime.now()
                    existing_issue.save()
            except IntegrityError as e:
                logger.error(f"IntegrityError while handling issue {issue.issue_hash}: {str(e)}", exc_info=True)

    def _generate_hash(self, file_path, node):
        """
        Generates a unique hash for a file path and nod so there's no overlap/ duplicates
        """
        # Extract details to make a unique identifier for the issue
        node_details = {
            'file_path': file_path,
            'line_number': getattr(node, 'lineno', 'unknown'),
            'node_type': type(node).__name__,
            'code_snippet': getattr(node, 's', '') if isinstance(node, ast.Str) else '',
        }
        
        # Convert details to a JSON string for hashing
        details_string = json.dumps(node_details, sort_keys=True)
        
        # Generate a hash
        return hashlib.sha256(details_string.encode('utf-8')).hexdigest()




    @sync_to_async
    def _create_issue(self, repository, file_path, node, issue_type, description):
        issue_hash = self._generate_hash(file_path, node)
        if CryptoIssue.objects.filter(issue_hash=issue_hash).exists():
            return None

        # Extract line number
        line_number = getattr(node, 'lineno', 0)

        # Extract code snippet (use AST node content for Python)
        code_snippet = (
            getattr(node, 's', None) if isinstance(node, ast.Str) else None
        ) or f"Code near line {line_number} in {file_path}"

        # Generate recommendation based on issue type
        recommendation = self._get_recommendation(issue_type, code_snippet)

        # Determine severity
        severity = self._get_severity(issue_type)

        # Create and save the issue
        issue = CryptoIssue(
            repository=repository,
            file_path=file_path,
            line_number=line_number,
            issue_type=issue_type,
            description=description,
            code_snippet=code_snippet,
            recommendation=recommendation,
            severity=severity,
            issue_hash=issue_hash,
        )
        issue.save()
        return issue




    def _get_recommendation(self, issue_type, code_snippet):
        recommendations = {
            'weak_cipher': f"The code uses a weak or deprecated cipher: {code_snippet}\nRecommendation: Use a strong, modern encryption algorithm like AES-256-GCM.",
            'hardcoded_secret': f"Hardcoded secret detected: {code_snippet}\nRecommendation: Store secrets securely using environment variables, a configuration management system, or a secrets management service. Avoid hardcoding secrets in the codebase.",
            'unsafe_random': f"Potentially unsafe random number generation: {code_snippet}\nRecommendation: Use a cryptographically secure random number generator suitable for your language/framework, such as os.urandom() or the secrets module in Python.",
            'insecure_mode': f"Insecure mode of operation detected: {code_snippet}\nRecommendation: Avoid using ECB mode as it is vulnerable to pattern-based attacks. Use secure modes like CBC with a secure padding scheme or an authenticated encryption mode like GCM.",
            'code_injection': f"Potential code injection vulnerability detected: {code_snippet}\nRecommendation: Avoid using eval() with untrusted input. Sanitize and validate any dynamic input used in eval() expressions.",
            'command_injection': f"Potential command injection vulnerability detected: {code_snippet}\nRecommendation: Avoid using exec() with untrusted input. Use safe alternatives like subprocess.run() with argument lists instead of shell=True.",
            'insecure_library': f"Potentially insecure cryptography library detected: {code_snippet}\nRecommendation: Ensure you are using a reputable, actively maintained cryptography library. Consider using high-level libraries that provide secure defaults. Regularly update dependencies to include security patches.",
            'insecure_ssl': f"Insecure SSL/TLS certificate verification detected: {code_snippet}\nRecommendation: Always use SSL.CERT_REQUIRED to enforce proper certificate validation. Avoid disabling certificate verification or allowing self-signed certificates in production.",
            'sensitive_data': f"Potential sensitive data in string literal detected: {code_snippet}\nRecommendation: Avoid storing sensitive information like passwords, secrets, or tokens in plain text. Use secure hashing, encryption, or a secrets management system as appropriate.",
            'weak_hash': f"Potentially weak custom hash function detected: {code_snippet}\nRecommendation: Use a strong, well-established hashing algorithm like SHA-256 or SHA-3 instead of creating custom hash functions. Consider using a standard library or a reputable third-party library for hashing."
        }
        return recommendations.get(issue_type, 'Review and update the code following secure coding practices and industry standards. Consult OWASP guidelines, language-specific security resources, and up-to-date cryptography best practices.')

    def _get_severity(self, issue_type):
        severity_map = {
            'weak_cipher': 'high', 
            'hardcoded_secret': 'critical',
            'unsafe_random': 'high',
            'insecure_mode': 'high',
            'code_injection': 'critical',
            'command_injection': 'critical', 
            'insecure_library': 'medium',
            'insecure_ssl': 'high',
            'sensitive_data': 'high',
            'weak_hash': 'medium'
        }
        return severity_map.get(issue_type, 'low')





class GitHubService:
    def __init__(self, token):
        self.token = token
        self.session = requests.Session()
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def fetch_issues(self, repo_url):
        """
        Fetch issues for a specific GitHub repository and cache the results.

        :param repo_url: The full URL of the GitHub repository.
        :return: List of issues for the repository.
        """
        cache_key = f"github_issues_{repo_url}"
        cached_issues = cache.get(cache_key)
        if cached_issues:
            logger.info(f"Using cached issues for repository {repo_url}.")
            return cached_issues

        # Convert GitHub web URL to API URL
        repo_name = repo_url.replace("https://github.com/", "")
        issues_url = f"https://api.github.com/repos/{repo_name}/issues"

        logger.debug(f"Fetching issues from {issues_url} with headers: {self.headers}")
        response = self.session.get(issues_url, headers=self.headers)

        if response.status_code != 200:
            logger.error(f"Failed to fetch issues for {repo_url}: {response.status_code}")
            logger.error(f"Response: {response.text}")  # Avoid .json() to handle non-JSON responses gracefully
            return []

        try:
            issues_data = response.json()
        except ValueError as e:
            logger.error(f"Error decoding JSON response for {repo_url}: {e}")
            return []

        logger.info(f"Fetched {len(issues_data)} issues for repository {repo_url}.")

        # Cache issues for 1 week
        cache.set(cache_key, issues_data, timeout=60 * 60 * 24 * 7)
        logger.debug(f"Cached issues for repository {repo_url} with key {cache_key}.")

        return issues_data

    def fetch_repositories(self):
        url = "https://api.github.com/search/repositories?q=is:open+issue&sort=created&order=desc"
        etag = cache.get('github_repos_etag')
        headers = self.headers.copy()
        if etag:
            headers['If-None-Match'] = etag

        logger.debug(f"Fetching repositories from {url} with headers: {headers}")
        response = self.session.get(url, headers=headers)

        # Handle 304 Not Modified (cached data is up-to-date)
        if response.status_code == 304:
            logger.info("No changes detected. Using cached repositories.")
            cached_repos = cache.get('github_repositories')
            if not cached_repos:
                logger.warning("No cached repositories found despite 304 response.")
            return cached_repos

        if response.status_code != 200:
            logger.error(f"Failed to fetch repositories: {response.status_code}")
            logger.error(f"Response: {response.json()}")
            return []

        repos_data = response.json().get('items', [])
        logger.info(f"Fetched {len(repos_data)} repositories from GitHub.")
        for repo_data in repos_data:
            owner_data = repo_data.get('owner')
            if not owner_data or not owner_data.get('login'):
                logger.error(f"Repository '{repo_data.get('name')}' is missing valid owner data.")
                continue

            owner = owner_data['login']
            repo_name = repo_data['name']
            html_url = repo_data['html_url']

            try:
                GitHubRepository.objects.update_or_create(
                    url=html_url,
                    defaults={
                        "name": repo_name,
                        "description": repo_data.get('description', ''),
                        "stars": repo_data.get('stargazers_count', 0),
                        "language": repo_data.get('language', ''),
                        "status": 'completed',
                        "visibility": 'public',
                    },
                )
                logger.debug(f"Saved repository: {repo_name}")
            except Exception as e:
                logger.error(f"Error saving repository {repo_name}: {e}")