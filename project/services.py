import re
import base64
import requests
import asyncio
import ast
from datetime import datetime
from .models import Repository, CryptoIssue
import logging
import os
logger = logging.getLogger(__name__)

class CryptoAnalyzer:

    def __init__(self, github_token):
        self.token = github_token
        self.headers = {'Authorization': f'token {github_token}'}
        self.session = requests.Session()

    def analyze_repository(self, repo_url):
        logger.info(f"Starting analysis for repository: {repo_url}")
        try:
            match = re.match(r'https://github.com/([^/]+)/([^/]+)', repo_url)
            if not match:
                raise ValueError('Invalid GitHub repository URL')

            owner, name = match.groups()
            repo, created = Repository.objects.get_or_create(
                owner=owner,
                name=name,
                defaults={'url': repo_url}
            )

            repo.status = 'analyzing'
            repo.save()

            asyncio.run(self.analyze_contents_async(repo, f'https://api.github.com/repos/{owner}/{name}/contents'))

            repo.status = 'completed'
            repo.save()
            logger.info(f"Analysis completed for repository: {repo_url}")
            return repo

        except Exception as e:
            logger.error(f"Error analyzing repository {repo_url}: {e}", exc_info=True)
            if repo:
                repo.status = 'error'
                repo.error_message = str(e)
                repo.save()
            raise

    async def analyze_contents_async(self, repo, contents_url, path_prefix=''):
        logger.info(f"Fetching contents from: {contents_url}")
        try:
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
        try:
            response = self.session.get(file_info['url'], headers=self.headers)
            response.raise_for_status()
            content = response.json()

            if content['encoding'] == 'base64':
                file_content = base64.b64decode(content['content']).decode('utf-8')
                await self._analyze_content(repo, file_path, file_content)
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}", exc_info=True)

    def _is_analyzable_file(self, filename):
        extensions = (
            '.py', '.js', '.java', '.go', '.rb', '.php',
            '.cpp', '.c', '.h', '.cs', '.ts', '.swift',
            '.m', '.scala', '.rs', '.kt', '.go'
        )
        return filename.lower().endswith(extensions)

    async def _analyze_content(self, repo, file_path, content):
        logger.info(f"Analyzing content for file: {file_path}")
        try:
            issues = []
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ['DES', 'RC4', 'MD5', 'SHA1', 'Blowfish', 'MD4', 'MD2', 'MD6']:
                        issues.append(self._create_issue(repo, file_path, node, 'weak_cipher', 'Weak or deprecated cryptographic algorithm detected'))
                    elif node.func.id in ['random', 'Math.random', 'rand', 'srand']:
                        issues.append(self._create_issue(repo, file_path, node, 'unsafe_random', 'Potentially unsafe random number generation'))
                    elif node.func.id == 'ECB':
                        issues.append(self._create_issue(repo, file_path, node, 'insecure_mode', 'Insecure mode of operation (ECB) detected'))
                    elif node.func.id == 'eval':
                        issues.append(self._create_issue(repo, file_path, node, 'code_injection', 'Potential code injection vulnerability detected'))
                    elif node.func.id == 'exec':
                        issues.append(self._create_issue(repo, file_path, node, 'command_injection', 'Potential command injection vulnerability detected'))
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.lower() in ['password', 'secret', 'key', 'token', 'credential']:
                            issues.append(self._create_issue(repo, file_path, node, 'hardcoded_secret', 'Potential hardcoded secret detected'))
                elif isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name.lower() in ['cryptography', 'pycrypto', 'pynacl', 'passlib']:
                            issues.append(self._create_issue(repo, file_path, node, 'insecure_library', 'Potentially insecure cryptography library detected'))
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'ssl':
                    if node.attr in ['CERT_NONE', 'CERT_OPTIONAL']:
                        issues.append(self._create_issue(repo, file_path, node, 'insecure_ssl', 'Insecure SSL/TLS certificate verification detected'))
                elif isinstance(node, ast.Str):
                    if re.search(r'\b(password|secret|key|token|credential)\b', node.s, re.IGNORECASE):
                        issues.append(self._create_issue(repo, file_path, node, 'sensitive_data', 'Potential sensitive data in string literal detected'))
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift):
                    issues.append(self._create_issue(repo, file_path, node, 'weak_hash', 'Potentially weak custom hash function detected'))
            if issues:
                logger.info(f"Detected {len(issues)} issues in {file_path}")
                await asyncio.to_thread(CryptoIssue.objects.bulk_create, issues)
        except Exception as e:
            logger.error(f"Error analyzing content for {file_path}: {e}", exc_info=True)

    def _create_issue(self, repo, file_path, node, issue_type, description):
        line_number = node.lineno
        code_snippet = ast.unparse(node)
        recommendation = self._get_recommendation(issue_type, code_snippet)
        return CryptoIssue(
            repository=repo,
            file_path=file_path,
            line_number=line_number,
            issue_type=issue_type,
            description=description,
            severity=self._get_severity(issue_type),
            code_snippet=code_snippet,
            recommendation=recommendation
        )

    def _get_recommendation(self, issue_type, code_snippet):
        if issue_type == 'weak_cipher':
            return f"The code uses a weak or deprecated cipher: {code_snippet}\nRecommendation: Use a strong, modern encryption algorithm like AES-256-GCM."
        elif issue_type == 'hardcoded_secret':
            return f"Hardcoded secret detected: {code_snippet}\nRecommendation: Store secrets securely using environment variables, a configuration management system, or a secrets management service. Avoid hardcoding secrets in the codebase."
        elif issue_type == 'unsafe_random':
            return f"Potentially unsafe random number generation: {code_snippet}\nRecommendation: Use a cryptographically secure random number generator suitable for your language/framework, such as os.urandom() or secrets module in Python."
        elif issue_type == 'insecure_mode':
            return f"Insecure mode of operation detected: {code_snippet}\nRecommendation: Avoid using ECB mode as it is vulnerable to pattern-based attacks. Use secure modes like CBC with a secure padding scheme or an authenticated encryption mode like GCM."
        elif issue_type == 'code_injection':
            return f"Potential code injection vulnerability detected: {code_snippet}\nRecommendation: Avoid using eval() with untrusted input. Sanitize and validate any dynamic input used in eval() expressions."
        elif issue_type == 'command_injection':  
            return f"Potential command injection vulnerability detected: {code_snippet}\nRecommendation: Avoid using exec() with untrusted input. Use safe alternatives like subprocess.run() with argument list instead of shell=True."
        elif issue_type == 'insecure_library':
            return f"Potentially insecure cryptography library detected: {code_snippet}\nRecommendation: Ensure you are using a reputable, actively maintained cryptography library. Consider using high-level libraries that provide secure defaults. Regularly update dependencies to include security patches."
        elif issue_type == 'insecure_ssl':
            return f"Insecure SSL/TLS certificate verification detected: {code_snippet}\nRecommendation: Always use SSL.CERT_REQUIRED to enforce proper certificate validation. Avoid disabling certificate verification or allowing self-signed certificates in production."
        elif issue_type == 'sensitive_data':
            return f"Potential sensitive data in string literal detected: {code_snippet}\nRecommendation: Avoid storing sensitive information like passwords, secrets, or tokens in plain text. Use secure hashing, encryption, or a secrets management system as appropriate."
        elif issue_type == 'weak_hash':
            return f"Potentially weak custom hash function detected: {code_snippet}\nRecommendation: Use a strong, well-established hashing algorithm like SHA-256 or SHA-3 instead of creating custom hash functions. Consider using a standard library or a reputable third-party library for hashing."
        else:
            return 'Review and update the code following secure coding practices and industry standards. Consult OWASP guidelines, language-specific security resources, and up-to-date cryptography best practices.'

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
        self.headers = {'Authorization': f'token {token}'}
        self.session = requests.Session()

    def sync_issues(self):
        try:
            repos = Repository.objects.all()
            for repo in repos:
                self.sync_repo_issues(repo)
        except Exception as e:
            raise Exception(f'Error syncing issues: {str(e)}')

    def sync_repo_issues(self, repo):
        try:
            url = f'https://api.github.com/repos/{repo.owner}/{repo.name}/issues'
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            issues = response.json()

            for issue in issues:
                self.create_or_update_issue(repo, issue)
        except Exception as e:
            raise Exception(f'Error syncing issues for repository {repo.url}: {str(e)}')

    def create_or_update_issue(self, repo, issue):
        try:
            crypto_issue, created = CryptoIssue.objects.get_or_create(
                repository=repo,
                issue_id=issue['id'],
                defaults={
                    'title': issue['title'],
                    'description': issue['body'],
                    'state': issue['state'],
                    'url': issue['html_url'],
                    # Add other fields as needed
                }
            )

            if not created:
                crypto_issue.title = issue['title']
                crypto_issue.description = issue['body']
                crypto_issue.state = issue['state']
                crypto_issue.url = issue['html_url']
                # Update other fields as needed
                crypto_issue.save()
        except Exception as e:
            raise Exception(f'Error creating or updating issue {issue["id"]}: {str(e)}')