#views.py

from django.views.generic import ListView, FormView, DetailView, CreateView
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.urls import reverse_lazy
from django.db.models import Count
from django.conf import settings
from .models import Repository, CryptoIssue, CVE, Message, IssueReport
from .forms import RepositoryForm, MessageForm, IssueReportForm
from .services import CryptoAnalyzer
from django.db import models
import asyncio
from asgiref.sync import sync_to_async

import logging

logger = logging.getLogger(__name__)



def message_create(request, repository_pk):
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
    repository = get_object_or_404(Repository, pk=repository_pk)
    issue_reports = IssueReport.objects.filter(repository=repository)
    return render(request, 'project/issue_report_list.html', {'repository': repository, 'issue_reports': issue_reports})


def repository_list(request):
    repositories = Repository.objects.all()
    return render(request, 'project/repository_list.html', {'repositories': repositories})

def repository_detail(request, pk):
    repository = get_object_or_404(Repository, pk=pk)
    return render(request, 'project/repository_detail.html', {'repository': repository})



class MessageCreateView(CreateView):
    model = Message
    form_class = MessageForm
    template_name = 'project/message_create.html'

    def form_valid(self, form):
        form.instance.repository_id = self.kwargs['repository_pk']
        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy('project:repository_detail', kwargs={'pk': self.kwargs['repository_pk']})


class IssueReportListView(ListView):
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
    
class IssueListView(ListView):
    template_name = 'project/issue_list.html'
    context_object_name = 'repositories'
    paginate_by = settings.PAGINATE_BY

    def get_queryset(self):
        return Repository.objects.filter(status='completed').order_by('-last_analyzed')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add statistics
        context['stats'] = {
            'total_repos': Repository.objects.count(),
            'completed_repos': Repository.objects.filter(status='completed').count(),
            'analyzing_repos': Repository.objects.filter(status='analyzing').count(),
            'error_repos': Repository.objects.filter(status='error').count(),
        }
        return context

class RepositoryAnalysisView(FormView):
    template_name = 'project/analyze.html'
    form_class = RepositoryForm
    success_url = reverse_lazy('project:repository-detail')  # Adjust this to the desired URL name

    def form_valid(self, form):
        logger.debug(f"Form submitted with data: {form.cleaned_data}")
        try:
            analyzer = CryptoAnalyzer(settings.GITHUB_TOKEN)
            repo = analyzer.analyze_repository(form.cleaned_data['repository_url'])
            logger.debug(f"Repository analysis successful: {repo}")
            messages.success(self.request, 'Repository analysis completed successfully')
            return redirect('project:repository-detail', pk=repo.pk)
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            messages.error(self.request, f"Error analyzing repository: {str(e)}")
            return self.form_invalid(form)

class RepositoryDetailView(DetailView):
    model = Repository
    template_name = 'project/repository_detail.html'
    context_object_name = 'repository'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        repository = self.object
        context['issues'] = CryptoIssue.objects.filter(repository=repository).order_by('-severity', 'checked_at')
        context['stats'] = {
            'total_issues': repository.issues.count(),
            'critical_issues': repository.issues.filter(severity='critical').count(),
            'high_issues': repository.issues.filter(severity='high').count(),
            'medium_issues': repository.issues.filter(severity='medium').count(),
            'low_issues': repository.issues.filter(severity='low').count(),
        }
        return context