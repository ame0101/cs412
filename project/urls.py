from django.urls import path
from . import views

app_name = 'project'

urlpatterns = [
    path('', views.IssueListView.as_view(), name='issue-list'),
    path('analyze/', views.RepositoryAnalysisView.as_view(), name='analyze'),
    path('repository/<int:pk>/', views.RepositoryDetailView.as_view(), name='repository-detail'),
    path('repositories/', views.repository_list, name='repository_list'),
    path('repositories/<int:pk>/', views.repository_detail, name='repository_detail'),
    path('repositories/<int:repository_pk>/messages/create/', views.message_create, name='message_create'),
    path('repositories/<int:repository_pk>/issue-reports/', views.issue_report_list, name='issue_report_list'),
    
]