

from django.urls import path
from . import views
from .views import RepositoryDetailView

# Define app namespace for reverse URL resolution
app_name = 'project'

urlpatterns = [
    # General Pages
    path('', views.homepage, name='home'),  # Homepage displaying repositories and stats
    path('login/', views.login_view, name='login'),  # Login page
    path('register/', views.register_view, name='register'),  # User registration page
    path('logout/', views.logout_view, name='logout'),  # Logout action
    path('your-repos/', views.your_repos, name='your_repos'),  # User's uploaded repositories page


    # Repository Management
    path('repository/<int:pk>/', views.repository_detail, name='repository_detail'), # Repository details
    path('repository/<int:pk>/analyze/', views.analyze_repository, name='analyze_repository'),  # Analyze a specific repository
    path('repository/<int:pk>/delete/', views.delete_repository, name='delete_repository'),  # Delete a specific repository
    path('repository/<int:pk>/toggle_visibility/', views.toggle_visibility, name='toggle_visibility'),  # Toggle repository visibility (public/private)
    path('repository/<int:pk>/issues/', views.user_repo_issue_list_view, name='user_repo_issue_list'),

    # Repository Analysis
    path('analyze/', views.analyze_repository_view, name='analyze_repository'),  # Analyze form page for new repositories
    path('analyze/', views.RepositoryAnalysisView.as_view(), name='analyze'),  # General analysis overview page

    # Comments Section
    path('repository/<int:pk>/add_comment/', views.add_comment, name='add_comment'),  # Add a new comment to a repository
    path('comment/delete/<int:pk>/', views.delete_comment, name='delete_comment'),  # Delete an existing comment
    path('comment/edit/', views.edit_comment, name='edit_comment'),  # Edit comment
    path('pending/<int:pk>/', views.pending_page, name='pending'),  # Pending page to show analysis in progress

    # Issues Section
    path('issues/<str:repo_name>/', views.github_issue_list_view, name='github_issue_list'),






    

]
