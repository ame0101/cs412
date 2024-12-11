import logging, asyncio, re, requests, os
from datetime import timedelta
from asgiref.sync import sync_to_async
from django.conf import settings  
from django.contrib import messages, auth
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.core.cache import cache
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage  
from django.db import models
from django.db.models import Count, Q
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.timezone import now
from django.views.generic import ListView, FormView, DetailView, CreateView
from rich import _console
from django.utils.http import urlsafe_base64_decode

from .forms import (
    RepositoryForm, MessageForm, IssueReportForm, RegisterForm,  
    LoginForm, RepositoryAnalysisForm,
)
from .models import (
    Repository, CryptoIssue, CVE, Message, IssueReport, 
    Comment, CachedGitHubRepository,  
)
from .services import CryptoAnalyzer, GitHubService


logger = logging.getLogger(__name__)

# User authentication views

def register_view(request):
    """Handle user registration"""

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  
            user.set_password(form.cleaned_data['password'])
            user.save()
            login(request, user)  # Log in user right after registering 
            messages.success(request, "Registration successful")
            return redirect('project:home')  # Send user to homepage
    else:
        form = RegisterForm()

    return render(request, 'project/register.html', {'form': form})


@login_required  
def your_repos(request):
    """Show user's repositories"""
    
    # Get repos owned by current user sorted by created date
    user_repos = Repository.objects.filter(owner=request.user).order_by('-created_at')
    return render(request, 'project/your_repos.html', {'repositories': user_repos})
    
def analyze_repo_redirect(request):  
    """Redirect if trying to analyze repo while not logged in"""

    return redirect('project:login')  # Send to login page

def login_view(request):
    """Handle user login"""

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password) 
            if user is not None:
                login(request, user)
                messages.success(request, "Login successful")  
                return redirect('project:home')  # Send to homepage
            else:
                messages.error(request, "Invalid username or password")
    else:
        form = LoginForm()
        
    return render(request, 'project/login.html', {'form': form})


def logout_view(request):
    """Log out the user"""

    logout(request)
    messages.success(request, "You have been logged out")
    return redirect('project:home')  # Send back to homepage


# Repository interaction views

def message_create(request, repository_pk):
    """Create a message for a repository"""

    repository = get_object_or_404(Repository, pk=repository_pk)
    if request.method == 'POST':
        form = MessageForm(request.POST) 
        if form.is_valid():
            message = form.save(commit=False)
            message.repository = repository
            message.save()
            return redirect('project:repository_detail', pk=repository_pk)
    else:
        form = MessageForm()

    return render(request, 'project/message_create.html', {'repository': repository, 'form': form})
    
    
def issue_report_list(request, repository_pk):  
    """List issue reports for a repository"""

    repository = get_object_or_404(Repository, pk=repository_pk)
    issue_reports = IssueReport.objects.filter(repository=repository)
    return render(request, 'project/issue_report_list.html', {'repository': repository, 'issue_reports': issue_reports})


@login_required
def repository_list(request):  
    """List all public repositories and user's own repositories"""

    # Repositories uploaded by the current user
    user_uploaded_repositories = Repository.objects.filter(uploaded_by=request.user) 
    
    # Repositories fetched from GitHub (uploaded_by is NULL)
    github_repositories = Repository.objects.filter(owner=None)
    
    context = {
        'user_uploaded_repositories': user_uploaded_repositories,
        'github_repositories': github_repositories,
        
    }
    return render(request, 'repository_list.html', context)


def repository_detail(request, pk):
    """Show repository details"""

    # Get repository by primary key  
    repository = get_object_or_404(Repository, pk=pk)
    
    # Check if the repository is private and the user does not own it
    if repository.visibility == 'private' and repository.owner != request.user: 
        return HttpResponseForbidden("You are not authorized to view this repository.")
    
    # If the repository status is 'analyzing', redirect to the pending page
    if repository.status == 'analyzing':
        return redirect('project:pending', pk=repository.pk)
    
    # Handle repository deletion request
    if request.method == 'POST' and 'delete_repository' in request.POST:  
        # Deleting the repository
        repository.delete()
        messages.success(request, "Repository has been successfully deleted.") 
        return redirect('project:home')  # Redirect to the home page after delete

    # Handle the confirmation message before deletion
    if request.method == 'POST' and 'confirm_delete' in request.POST:
        messages.warning(request, "Are you sure you want to delete this repository? This action cannot be undone.")  
    
    next_url = request.GET.get('next', reverse('project:home'))
    
    # Render the repository details page
    return render(request, 'project/repository_detail.html', {
        'repository': repository,
        'next_url': next_url,
    })


def github_issue_list_view(request, repo_name):  
    """View for listing GitHub issues using GitHub API"""

    page = int(request.GET.get('page', 1))
    per_page = 10

    from .services import GitHubService

    # Initialize GitHub service
    github_service = GitHubService(settings.GITHUB_TOKEN)

    try:
        # Fetch issues with pagination
        repo_url = f"https://github.com/{repo_name}"
        issues_url = f"https://api.github.com/repos/{repo_name}/issues" 
        params = {
            'state': 'all',
            'per_page': per_page,
            'page': page
        }

        issues = github_service.fetch_issues(issues_url)
        if not issues:
            messages.warning(request, "No issues found for the repository.")
            return redirect('project:home')

        # Handle pagination manually for GitHub 
        total_pages = 1
        if 'Link' in github_service.session.headers:
            links = requests.utils.parse_header_links(github_service.session.headers['Link'])
            for link in links:
                if link.get('rel') == 'last':  
                    last_url = link['url']
                    last_page = int(re.search(r'page=(\d+)', last_url).group(1))
                    total_pages = min(10, last_page) 

        # Custom paginator for GitHub   
        class GitHubPaginator:
            def __init__(self, current_page, total_pages):
                self.number = current_page  
                self.num_pages = total_pages

            def page_range(self):  
                return range(1, self.num_pages + 1)

            @property  
            def has_next(self):
                return self.number < self.num_pages

            @property
            def has_previous(self):  
                return self.number > 1  

            def next_page_number(self):
                return self.number + 1

            def previous_page_number(self):  
                return self.number - 1

        paginator = GitHubPaginator(page, total_pages)

        context = {
            'repo_name': repo_name,  
            'issues': issues[(page - 1) * per_page:page * per_page],  # Paginate issues
            'page_obj': paginator,  
            'is_paginated': total_pages > 1
        }

        return render(request, 'project/github_issue_list.html', context)

    except requests.RequestException as e:
        messages.error(request, f"Failed to fetch issues: {str(e)}")
        return redirect('project:home')
        
        
def user_repo_issue_list_view(request, pk):
    """View for listing issues for a user-uploaded repository"""

    repository = get_object_or_404(Repository, pk=pk)

    if repository.visibility == 'private' and repository.owner != request.user:
        return HttpResponseForbidden("You are not authorized to view this repository.")

    severity_filter = request.GET.get('severity')  
    issues = repository.issues.all().order_by('-created_at')

    if severity_filter:
        issues = issues.filter(severity=severity_filter)

    paginator = Paginator(issues, 10)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    severity_choices = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),  
        ('critical', 'Critical'),
    ]

    # Calculate the stats for the repository
    total_issues = issues.count()
    low_issues = issues.filter(severity='low').count() 
    medium_issues = issues.filter(severity='medium').count()
    high_issues = issues.filter(severity='high').count()
    critical_issues = issues.filter(severity='critical').count()

    context = {
        'repository': repository,
        'page_obj': page_obj,  
        'severity_choices': severity_choices,
        'selected_severity': severity_filter,
        'stats': {
            'total_issues': total_issues,  
            'low_issues': low_issues,
            'medium_issues': medium_issues,
            'high_issues': high_issues,  
            'critical_issues': critical_issues
        }
    }

    return render(request, 'project/user_repo_issue_list.html', context)


# Generic class-based views

class MessageCreateView(CreateView):
    """Class-based view for creating a message"""

    model = Message
    form_class = MessageForm
    template_name = 'project/message_create.html'

    def form_valid(self, form):
        form.instance.repository_id = self.kwargs['repository_pk']  
        return super().form_valid(form)  

    def get_success_url(self): 
        return reverse_lazy('project:repository_detail', kwargs={'pk': self.kwargs['repository_pk']})


class IssueReportListView(ListView):
    """Class-based view for listing issue reports"""

    model = IssueReport  
    template_name = 'project/issue_report_list.html'
    context_object_name = 'issue_reports'
    paginate_by = 10

    def get_queryset(self):
        repository_pk = self.kwargs['repository_pk']  
        return IssueReport.objects.filter(repository_id=repository_pk)

    def get_context_data(self, **kwargs):  
        context = super().get_context_data(**kwargs) 
        context['repository'] = get_object_or_404(Repository, pk=self.kwargs['repository_pk'])
        return context


class RepositoryListView(ListView):
    """Class-based view for listing repositories with filters"""
  
    model = Repository
    template_name = 'project/repository_list.html'
    context_object_name = 'repositories'

    def get_queryset(self):
        queryset = super().get_queryset().filter(status='completed')  
        severity_filter = self.request.GET.get('severity')  
        language_filter = self.request.GET.get('language')
        
        if severity_filter:
            queryset = queryset.filter(issues__severity=severity_filter).distinct()
        if language_filter:
            queryset = queryset.filter(language=language_filter).distinct()

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Pass severity choices to template
        context['severity_choices'] = [
            ('low', 'Low'),
            ('medium', 'Medium'), 
            ('high', 'High'),
            ('critical', 'Critical'),
        ]  
        # Pass language choices to template
        context['language_choices'] = [
            ('python', 'Python'),
            ('javascript', 'JavaScript'),
            ('java', 'Java'),  
            ('go', 'Go'),
            ('ruby', 'Ruby'),
            ('php', 'PHP'),
            ('c++', 'C++'),  
            ('c', 'C'), 
            ('typescript', 'TypeScript'),
            ('swift', 'Swift'),
            ('scala', 'Scala'), 
        ]
        context['selected_severity'] = self.request.GET.get('severity', '')
        context['selected_language'] = self.request.GET.get('language', '')

        # Add repo and issue stats to context
        context['stats'] = {
            'total_repos': Repository.objects.filter(status='completed').count(),
            'low_issues': CryptoIssue.objects.filter(severity='low').count(),
            'medium_issues': CryptoIssue.objects.filter(severity='medium').count(),
            'high_issues': CryptoIssue.objects.filter(severity='high').count(),
            'critical_issues': CryptoIssue.objects.filter(severity='critical').count(),
        }  
        return context


class RepositoryAnalysisView(FormView):  
    """Form view for analyzing a repository"""

    template_name = 'project/analyze.html'
    form_class = RepositoryForm
    success_url = reverse_lazy('project:repository_detail')  # URL to go to after submitting

    def form_valid(self, form):
        logger.debug(f"Form submitted with data: {form.cleaned_data}")  
        try:
            analyzer = CryptoAnalyzer(settings.GITHUB_TOKEN)
            repo = analyzer.analyze_repository(form.cleaned_data['repository_url'])
            logger.debug(f"Repository analysis successful: {repo}") 
            messages.success(self.request, 'Repository analysis completed successfully')
            return redirect('project:repository_detail', pk=repo.pk)
        except Exception as e:
            logger.error(f"Error during analysis: {e}")  
            messages.error(self.request, f"Error analyzing repository: {str(e)}")
            return self.form_invalid(form)


def analyze_repository(self, request, repo_url):
    """Analyze repository"""
    
    logger.info(f"Starting analysis for repository: {repo_url}") 
    try:
        # Validate the GitHub repository URL using regex  
        match = re.match(r'https://github.com/([^/]+)/([^/]+)', repo_url)
        if not match:
            raise ValueError('Invalid GitHub repository URL')

        owner, name = match.groups()
        
        # Create or retrieve the repository from the database
        repo, created = Repository.objects.get_or_create(
            name=name,url=repo_url,
            defaults={
                'owner': None,  # Set owner to None for new repositories
                'status': 'analyzing',  # Set status to analyzing when the repository is created
            }
        )

        if not created:
            # Repository already exists
            logger.info(f"Repository already exists: {repo.full_name}")
            return repo, False

        # Update repository status to 'analyzing'
        repo.status = 'analyzing'
        repo.save()

        # Simulate repository content analysis (replace with your actual analysis function)
        contents_url = f"https://api.github.com/repos/{owner}/{name}/contents"
        asyncio.run(self.analyze_contents_async(repo, contents_url))  # Run async analysis

        # After analysis, set status to 'completed'
        repo.status = 'completed'
        repo.last_analyzed = now()
        repo.save()

        logger.info(f"Analysis completed for repository: {repo.full_name}")

        # Redirect to the pending page (to show analyzing status until it's complete)
        return redirect('project:pending', pk=repo.pk)

    except Exception as e:
        # Log error and set repository status to 'error' if something goes wrong
        logger.error(f"Error analyzing repository {repo_url}: {str(e)}")
        if 'repo' in locals():
            repo.status = 'error'
            repo.error_message = str(e)
            repo.save()
        # Notify the user of the error
        messages.error(self.request, f"Error analyzing repository: {e}")
        return redirect('project:analyze')  # Redirect back to the analyze page if an error occurs


def pending_page(request, pk):
    """Page to show analysis status"""

    repository = get_object_or_404(Repository, pk=pk)

    if repository.status == 'completed':
        # Analysis is complete, redirect to the repository detail page
        return redirect('project:repository_detail', pk=repository.pk)
    elif repository.status == 'error':
        # Analysis failed, display the error message
        messages.error(request, f"Error analyzing repository: {repository.error_message}")
        return redirect('project:repository_detail', pk=repository.pk)
    else:
        # Analysis is still in progress, render the pending page
        return render(request, 'project/pending.html', {'repository': repository})


@login_required
def analyze_repository_view(request):
    """View to analyze a repository, must be logged in""" 

    if request.method == 'POST':
        form = RepositoryForm(request.POST)
        if form.is_valid():
            repository_url = form.cleaned_data['repository_url']
            try:
                analyzer = CryptoAnalyzer(settings.GITHUB_TOKEN)
                repo = analyzer.analyze_repository(repository_url)

                # Set repo owner to current user if no owner
                if not repo.owner:
                    repo.owner = request.user 
                    repo.save()

                messages.success(request, 'Repository analysis completed successfully.')
                return redirect('project:repository_detail', pk=repo.pk)

            except ValueError as e:
                messages.error(request, str(e))  # Show validation errors
            except Exception as e:
                logger.exception(f"Error during analysis for {repository_url}: {e}")
                messages.error(request, "An unexpected error occurred during analysis.")  
    else:
        form = RepositoryForm()

    return render(request, 'project/analyze.html', {'form': form})


class RepositoryDetailView(ListView):
    """Class-based view for repository details"""

    template_name = 'project/repository_detail.html'
    context_object_name = 'issues' 
    paginate_by = settings.PAGINATE_BY  # Page size from settings

    def get_queryset(self):
        """Get issues for repository, filter by severity if selected"""

        repository = get_object_or_404(Repository, pk=self.kwargs['pk'])
        queryset = CryptoIssue.objects.filter(repository=repository)
        severity_filter = self.request.GET.get('severity')
        if severity_filter:  
            queryset = queryset.filter(severity=severity_filter)
        return queryset.order_by('severity', 'checked_at')

    def get_context_data(self, **kwargs):  
        """Add repository details and stats to context"""

        context = super().get_context_data(**kwargs)
        repository = get_object_or_404(Repository, pk=self.kwargs['pk'])

        context['repository'] = repository
        context['severity_choices'] = [
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),  
        ]
        context['selected_severity'] = self.request.GET.get('severity', '')
        context['stats'] = {
            'total_issues': self.get_queryset().count(),
            'critical_issues': self.get_queryset().filter(severity='critical').count(),
            'high_issues': self.get_queryset().filter(severity='high').count(), 
            'medium_issues': self.get_queryset().filter(severity='medium').count(),
            'low_issues': self.get_queryset().filter(severity='low').count(),
       }
        return context


def github_issue_list_view(request, repo_name):
    """View to fetch and display issues for a GitHub repository using the GitHub API."""

    try:
        # Decode base64 encoded repo_name
        decoded_name = urlsafe_base64_decode(repo_name).decode()
        owner, repo = decoded_name.split('/')
    except Exception as e:
        messages.error(request, "Invalid Repository") 
        return redirect('project:home')

    # Fetch issues  
    token = settings.GITHUB_TOKEN
    page_number = request.GET.get('page', 1) 
    issues = fetch_github_issues(f"{owner}/{repo}", token, page_number)

    # Paginate issues
    paginator = Paginator(issues, 10)  # Show 10 issues per page
    page_obj = paginator.get_page(page_number)

    # Render the template
    return render(request, 'project/github_issue_list.html', {
        'repo_name': f"{owner}/{repo}",
        'issues': page_obj,
    })


def fetch_github_issues(repo_full_name, token, page_number):
    """Fetch issues from GitHub API"""

    url = f"https://api.github.com/repos/{repo_full_name}/issues?page={page_number}&per_page=10"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",  
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return []


def fetch_and_cache_github_repositories():  
    """Fetch and cache GitHub repositories""" 

    token = settings.GITHUB_TOKEN
    github_service = GitHubService(token)
    try:
        github_repositories = github_service.fetch_repositories()
        CachedGitHubRepository.objects.all().delete()  # Remove old cached data
        for repo in github_repositories:
            CachedGitHubRepository.objects.create(
                name=repo['name'],
                description=repo['description'],
                html_url=repo['html_url'], 
                open_issues_count=repo['open_issues_count'],
                last_updated=now()
            )
        logger.info("INFO: GitHub repositories cached successfully.")
    except Exception as e:
        logger.error(f"ERROR: Failed to fetch and cache GitHub repositories: {e}")


def homepage(request):
    """Homepage view to show repositories, filters, and stats"""

    logger.info("INFO: Homepage function accessed.")

    # Check for cached GitHub repos updated in the last 2 weeks
    two_weeks_ago = now() - timedelta(weeks=2) 
    cached_repositories = CachedGitHubRepository.objects.filter(last_updated__gte=two_weeks_ago)

    # Paginate GitHub-fetched repositories  
    github_paginator = Paginator(cached_repositories, 10)  # Show 10 repositories per page
    github_page_number = request.GET.get('github_page') 
    github_page_obj = github_paginator.get_page(github_page_number)

    if not cached_repositories.exists():
        logger.info("INFO: No recent cached repositories found. Fetching from GitHub API.")
        token = settings.GITHUB_TOKEN
        github_service = GitHubService(token)  
        
        try:
            github_repositories = github_service.fetch_repositories() 
            logger.info(f"INFO: Fetched {len(github_repositories)} GitHub repositories.")
            
            # Remove old data and save new
            CachedGitHubRepository.objects.all().delete()  
            for repo in github_repositories:
                owner = repo['owner']['login']  # Extract owner
                CachedGitHubRepository.objects.create(  
                    owner=owner,
                    name=repo['name'],
                    description=repo['description'],
                    html_url=repo['html_url'],
                    open_issues_count=repo['open_issues_count'],  
                )
            cached_repositories = CachedGitHubRepository.objects.all()  # Refresh data
            logger.info(f"INFO: Successfully cached {cached_repositories.count()} repositories.") 
        except Exception as e:
            logger.error(f"ERROR: Failed to fetch GitHub repositories: {e}")
            cached_repositories = CachedGitHubRepository.objects.none()  # Empty data set
            
    for repo in cached_repositories:  
        if repo.formatted_name:
            logger.debug(f"Repo: {repo.name}, Formatted Name: {repo.formatted_name}")
        else:
            logger.warning(f"Repo {repo.name} is missing owner or name: Owner: {repo.owner}, Name: {repo.name}")

    # Apply filters for user repos
    severity_filter = request.GET.get('severity')
    language_filter = request.GET.get('language')

    repositories = Repository.objects.filter(status='completed') 
    if severity_filter:  
        logger.debug(f"DEBUG: Applying severity filter: {severity_filter}")
        repositories = repositories.filter(issues__severity=severity_filter).distinct()
    if language_filter:
        logger.debug(f"DEBUG: Applying language filter: {language_filter}")
        repositories = repositories.filter(language=language_filter).distinct()  

    # Add stats for each repo
    for repo in repositories:  
        repo.total_issues = CryptoIssue.objects.filter(repository=repo).count()
        repo.low_issues = CryptoIssue.objects.filter(repository=repo, severity='low').count()
        repo.medium_issues = CryptoIssue.objects.filter(repository=repo, severity='medium').count()
        repo.high_issues = CryptoIssue.objects.filter(repository=repo, severity='high').count()
        repo.critical_issues = CryptoIssue.objects.filter(repository=repo, severity='critical').count()

    # Paginate results  
    page = request.GET.get('page', 1)
    paginator = Paginator(repositories, 10)  
    try:
        repositories = paginator.page(page)
    except PageNotAnInteger:
        repositories = paginator.page(1)
    except EmptyPage:
        repositories = paginator.page(paginator.num_pages)

    # Prepare context data
    context = {
        'github_repositories': github_page_obj,  # Pass paginated GitHub repositories
        'repositories': repositories, 
        'severity_choices': [
            ('low', 'Low'),
            ('medium', 'Medium'), 
            ('high', 'High'),  
            ('critical', 'Critical'),
        ],
        'language_choices': [
            ('python', 'Python'),
            ('javascript', 'JavaScript'),
            ('java', 'Java'),
            ('go', 'Go'), 
            ('ruby', 'Ruby'),  
            ('php', 'PHP'),
            ('c++', 'C++'),
            ('c', 'C'),
            ('typescript', 'TypeScript'),  
            ('swift', 'Swift'), 
            ('scala', 'Scala'),
        ],  
        'selected_severity': severity_filter or '',
        'selected_language': language_filter or '',
        'stats': {
            'total_repos': Repository.objects.filter(status='completed').count(),
            'low_issues': CryptoIssue.objects.filter(severity='low').count(),
            'medium_issues': CryptoIssue.objects.filter(severity='medium').count(),
            'high_issues': CryptoIssue.objects.filter(severity='high').count(),
            'critical_issues': CryptoIssue.objects.filter(severity='critical').count(), 
        },
        'github_page_obj': github_page_obj,
        'is_paginated': paginator.num_pages > 1,
        'page_obj': repositories,
        
    }

    logger.debug(f"DEBUG: Homepage context prepared with {repositories.paginator.count} repositories total.")
    return render(request, 'project/repository_list.html', context)


def delete_repository(request, pk):
    """Delete a repository"""

    repository = get_object_or_404(Repository, pk=pk)

    # Check if user owns the repository
    if repository.owner != request.user:
        return HttpResponseForbidden("You are not authorized to delete this repository.")

    # Delete the repository 
    repository.delete()

    # Show success message
    messages.success(request, "Repository deleted successfully.")

    return redirect('project:your_repos')  # Go back to user's repositories


@login_required  
def toggle_visibility(request, pk):
    """Toggle repository visibility"""

    repo = get_object_or_404(Repository, pk=pk, owner=request.user) 
    repo.toggle_visibility()
    return redirect('project:repository_detail', pk=repo.pk)


@login_required
def add_comment(request, pk):
    """Add a comment to a repository"""

    repository = get_object_or_404(Repository, pk=pk)
    if repository.visibility != 'public':
        return HttpResponseForbidden("You can't comment on a private repository.")

    content = request.POST.get('content')
    parent_id = request.POST.get('parent_id')
    parent = None

    if parent_id:
        parent = get_object_or_404(Comment, id=parent_id, repository=repository)

    Comment.objects.create(repository=repository, user=request.user, content=content, parent=parent)
    redirect_url = request.POST.get('redirect_url', f'/project/repository/{pk}/')
    return redirect(redirect_url)


@login_required  
def edit_comment(request):
    """Edit a user's comment"""

    if request.method == 'POST':
        comment_id = request.POST.get('comment_id')
        content = request.POST.get('content')
        comment = get_object_or_404(Comment, pk=comment_id, user=request.user)
        comment.content = content  
        comment.save()
        return redirect('project:repository_detail', pk=comment.repository.pk)


@login_required
def delete_comment(request, pk):  
    """Delete a user's comment"""

    comment = get_object_or_404(Comment, pk=pk)

    # Check if user owns the comment
    if comment.user != request.user:
        return HttpResponseForbidden("You cannot delete this comment.")

    repository_pk = comment.repository.pk
    comment.delete()

    # Go back to repository details
    return redirect('project:repository_detail', pk=repository_pk)

