# voter_analytics/views.py

from django.shortcuts import render
from django.views.generic import ListView, DetailView
from .models import Voter
from django.db import models   # Add this line
from django.db.models import Q
from django.utils import timezone
import plotly.express as px
import plotly.offline as opy
import plotly.graph_objects as go


class VoterListView(ListView):
    """
    View to display a list of Voter records with filtering options.
    """
    model = Voter
    template_name = 'voter_analytics/voter_list.html'
    context_object_name = 'voters'
    paginate_by = 100

    def get_queryset(self):
        """
        Override the default queryset to implement filtering.
        """
        qs = super().get_queryset()

        # Get filter parameters
        party = self.request.GET.get('party_affiliation')
        min_dob = self.request.GET.get('min_dob')
        max_dob = self.request.GET.get('max_dob')
        voter_score = self.request.GET.get('voter_score')
        elections = ['v20state', 'v21town', 'v21primary', 'v22general', 'v23town']

        # Apply filters
        if party:
            qs = qs.filter(party_affiliation=party)

        if min_dob:
            qs = qs.filter(date_of_birth__gte=min_dob)

        if max_dob:
            qs = qs.filter(date_of_birth__lte=max_dob)

        if voter_score:
            qs = qs.filter(voter_score=voter_score)

        for election in elections:
            if self.request.GET.get(election):
                filter_kwargs = {election: True}
                qs = qs.filter(**filter_kwargs)

        return qs.order_by('last_name', 'first_name')

    def get_context_data(self, **kwargs):
        """
        Add filter options to the context.
        """
        context = super().get_context_data(**kwargs)
        context['party_affiliations'] = Voter.objects.values_list('party_affiliation', flat=True).distinct()
        current_year = timezone.now().year
        years = range(current_year - 120, current_year + 1)
        context['years'] = years
        context['voter_scores'] = range(0, 6)
        return context

class VoterDetailView(DetailView):
    """
    View to display details of a single Voter record.
    """
    model = Voter
    template_name = 'voter_analytics/voter_detail.html'
    context_object_name = 'voter'

    def get_context_data(self, **kwargs):
        """
        Add additional context data.
        """
        context = super().get_context_data(**kwargs)
        voter = context['voter']
        # Generate Google Maps link
        address = voter.full_address.replace(' ', '+')
        google_maps_url = f"https://www.google.com/maps/search/?api=1&query={address}"
        context['google_maps_url'] = google_maps_url
        return context

class GraphsView(ListView):
    """
    View to display graphs of voter data with filtering options.
    """
    model = Voter
    template_name = 'voter_analytics/graphs.html'
    context_object_name = 'voters'

    def get_queryset(self):
        """
        Reuse the filtering logic from VoterListView.
        """
        qs = super().get_queryset()

        # Get filter parameters
        party = self.request.GET.get('party_affiliation')
        min_dob = self.request.GET.get('min_dob')
        max_dob = self.request.GET.get('max_dob')
        voter_score = self.request.GET.get('voter_score')
        elections = ['v20state', 'v21town', 'v21primary', 'v22general', 'v23town']

        # Apply filters
        if party:
            qs = qs.filter(party_affiliation=party)

        if min_dob:
            qs = qs.filter(date_of_birth__gte=min_dob)

        if max_dob:
            qs = qs.filter(date_of_birth__lte=max_dob)

        if voter_score:
            qs = qs.filter(voter_score=voter_score)

        for election in elections:
            if self.request.GET.get(election):
                filter_kwargs = {election: True}
                qs = qs.filter(**filter_kwargs)

        return qs

    def get_context_data(self, **kwargs):
        """
        Generate graphs and add them to the context.
        """
        context = super().get_context_data(**kwargs)
        qs = self.get_queryset()

        # Year of Birth Histogram
        birth_years = qs.values_list('date_of_birth', flat=True)
        birth_years = [date.year for date in birth_years]
        fig1 = px.histogram(birth_years, nbins=30, title='Distribution of Voters by Year of Birth')
        graph1 = opy.plot(fig1, auto_open=False, output_type='div')
        context['birth_year_histogram'] = graph1

        # Party Affiliation Pie Chart
        party_counts = qs.values('party_affiliation').order_by().annotate(count=models.Count('party_affiliation'))
        fig2 = px.pie(party_counts, names='party_affiliation', values='count', title='Party Affiliation Distribution')
        graph2 = opy.plot(fig2, auto_open=False, output_type='div')
        context['party_affiliation_pie_chart'] = graph2

        # Election Participation Histogram
        elections = ['v20state', 'v21town', 'v21primary', 'v22general', 'v23town']
        participation = {}
        for election in elections:
            participation[election] = qs.filter(**{election: True}).count()
        fig3 = go.Figure([go.Bar(x=list(participation.keys()), y=list(participation.values()))])
        fig3.update_layout(title='Election Participation', xaxis_title='Election', yaxis_title='Number of Voters')
        graph3 = opy.plot(fig3, auto_open=False, output_type='div')
        context['election_participation_bar_chart'] = graph3

        # Add filter options to the context
        context['party_affiliations'] = Voter.objects.values_list('party_affiliation', flat=True).distinct()
        current_year = timezone.now().year
        years = range(current_year - 120, current_year + 1)
        context['years'] = years
        context['voter_scores'] = range(0, 6)

        return context
