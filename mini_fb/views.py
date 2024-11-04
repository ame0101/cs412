from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.views.generic.edit import CreateView
from django.views import View
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from .models import Profile, StatusMessage, Image, Friend
from .forms import CreateProfileForm, CreateStatusMessageForm, UpdateProfileForm, UpdateStatusMessageForm

from django.contrib.auth.mixins import LoginRequiredMixin

class ShowFriendSuggestionsView(LoginRequiredMixin, DetailView):
    model = Profile
    template_name = 'friend_suggestions.html'
    context_object_name = 'profile'

    def get_object(self, queryset=None):
        return self.request.user.profile

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = self.get_object()
        suggestions = profile.get_friend_suggestions()
        context['suggestions'] = suggestions
        return context

class ShowAllProfilesView(ListView):
    model = Profile
    template_name = 'mini_fb/show_all_profiles.html'
    context_object_name = 'profiles'

class ShowProfilePageView(DetailView):
    model = Profile
    template_name = 'mini_fb/show_profile.html'
    context_object_name = 'profile'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = self.get_object()
        context['friends'] = profile.get_friends()
        context['friend_suggestions'] = profile.get_friend_suggestions()
        context['news_feed'] = profile.get_news_feed()
        return context

class CreateProfileView(LoginRequiredMixin, CreateView):
    model = Profile
    form_class = CreateProfileForm
    template_name = 'mini_fb/create_profile_form.html'

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        return reverse('show_profile', kwargs={'pk': self.object.pk})
    
    
class UpdateProfileView(LoginRequiredMixin, UpdateView):
    model = Profile
    form_class = UpdateProfileForm
    template_name = 'mini_fb/update_profile_form.html'

    def get_object(self, queryset=None):
        return self.request.user.profile

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        return reverse('show_profile', kwargs={'pk': self.object.pk})

class DeleteProfileView(LoginRequiredMixin, DeleteView):
    model = Profile
    template_name = 'mini_fb/delete_profile_form.html'
    context_object_name = 'profile'

    def get_success_url(self):
        messages.success(self.request, "Profile deleted successfully.")
        return reverse('show_all_profiles')

class CreateStatusMessageView(LoginRequiredMixin, CreateView):
    model = StatusMessage
    form_class = CreateStatusMessageForm
    template_name = 'mini_fb/create_status_form.html'

    def get_object(self, queryset=None):
        return self.request.user.profile

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = self.get_object()
        context['profile'] = profile
        return context

    def form_valid(self, form):
        profile = self.get_object()
        form.instance.profile = profile
        response = super().form_valid(form)

        files = self.request.FILES.getlist('files')
        for file in files:
            Image.objects.create(
                status_message=self.object,
                image_file=file
            )

        messages.success(self.request, "Status message posted successfully.")
        return response

    def get_success_url(self):
        return reverse('show_profile', kwargs={'pk': self.object.pk})

class UpdateStatusMessageView(LoginRequiredMixin, UpdateView):
    model = StatusMessage
    form_class = UpdateStatusMessageForm
    template_name = 'mini_fb/update_status_form.html'
    context_object_name = 'status_message'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        messages.success(self.request, "Status message updated successfully.")
        return reverse('show_profile', kwargs={'pk': self.object.profile.pk})

class DeleteStatusMessageView(LoginRequiredMixin, DeleteView):
    model = StatusMessage
    template_name = 'mini_fb/delete_status_form.html'
    context_object_name = 'status_message'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        messages.success(self.request, "Status message deleted successfully.")
        return reverse('show_profile', kwargs={'pk': self.object.profile.pk})


class CreateFriendView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, other_pk, *args, **kwargs):
        try:
            profile = request.user.profile
        except (Profile.DoesNotExist, AttributeError):

            messages.error(request, "You need to create a profile before adding friends.")
            return redirect('create_profile')

        other_profile = get_object_or_404(Profile, pk=other_pk)

        if profile == other_profile:
            messages.error(request, "You cannot add yourself as a friend.")
            return redirect('show_profile', pk=profile.pk)

        friendship_exists = Friend.objects.filter(
            profile1=profile, profile2=other_profile
        ).exists() or Friend.objects.filter(
            profile1=other_profile, profile2=profile
        ).exists()

        if friendship_exists:
            messages.warning(request, "You are already friends with this profile.")
            return redirect('show_profile', pk=profile.pk)

        Friend.objects.create(profile1=profile, profile2=other_profile)
        messages.success(request, f"You are now friends with {other_profile.first_name} {other_profile.last_name}.")
        return redirect('show_profile', pk=profile.pk)
    

class ShowNewsFeedView(LoginRequiredMixin, DetailView):
    model = Profile
    template_name = 'mini_fb/news_feed.html'
    context_object_name = 'profile'

    def get_object(self, queryset=None):
        return self.request.user.profile

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = self.get_object()
        context['news_feed'] = profile.get_news_feed()
        return context

class RegistrationView(CreateView):
    form_class = UserCreationForm
    template_name = 'mini_fb/register.html'

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect('create_profile')