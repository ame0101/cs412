from django.shortcuts import render
from django.views.generic import ListView, DetailView
from .models import Voter
from django.db.models import Count, Q
from django.utils import timezone
import plotly.express as px
import plotly.offline as opy
import plotly.graph_objects as go


class VoterListView(ListView):
    model = Voter
    template_name = 'voter_analytics/voter_list.html'
    context_object_name = 'voters'
    paginate_by = 100

    def get_queryset(self):
        qs = super().get_queryset()
        party = self.request.GET.get('party_affiliation')
        min_year = self.request.GET.get('min_year')
        max_year = self.request.GET.get('max_year')
        voter_score = self.request.GET.get('voter_score')
        elections = ['v20state', 'v21town', 'v21primary', 'v22general', 'v23town']

        if party:
            qs = qs.filter(party_affiliation=party)

        if min_year:
            qs = qs.filter(date_of_birth__year__gte=min_year)

        if max_year:
            qs = qs.filter(date_of_birth__year__lte=max_year)

        if voter_score:
            qs = qs.filter(voter_score=voter_score)

        for election in elections:
            if self.request.GET.get(election) == 'on':
                qs = qs.filter(**{election: True})

        return qs.order_by('last_name', 'first_name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['party_affiliations'] = Voter.objects.values_list('party_affiliation', flat=True).distinct()
        current_year = timezone.now().year
        context['years'] = range(1910, 2007)  # Fixed to match the years you wanted
        context['voter_scores'] = range(6)
        return context

class VoterDetailView(DetailView):
    model = Voter
    template_name = 'voter_analytics/voter_detail.html'
    context_object_name = 'voter'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        voter = context['voter']
        address = voter.full_address.replace(' ', '+')
        google_maps_url = f"https://www.google.com/maps/search/?api=1&query={address}"
        context['google_maps_url'] = google_maps_url
        return context
class GraphsView(VoterListView):
    """
    View to display graphs of voter data using filtering options from VoterListView.
    """
    template_name = 'voter_analytics/graphs.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)  
        qs = self.get_queryset()  

        birth_years = qs.values_list('date_of_birth', flat=True)
        birth_years = [date.year for date in birth_years if date]
        fig1 = px.histogram(birth_years, nbins=30, title='Distribution of Voters by Year of Birth')
        graph1 = opy.plot(fig1, auto_open=False, output_type='div')
        context['birth_year_histogram'] = graph1

        party_counts = qs.values('party_affiliation').annotate(count=Count('party_affiliation'))
        fig2 = px.pie(party_counts, names='party_affiliation', values='count', title='Party Affiliation Distribution')
        graph2 = opy.plot(fig2, auto_open=False, output_type='div')
        context['party_affiliation_pie_chart'] = graph2

        elections = ['v20state', 'v21town', 'v21primary', 'v22general', 'v23town']
        participation = {election: qs.filter(**{election: True}).count() for election in elections}
        fig3 = go.Figure([go.Bar(x=list(participation.keys()), y=list(participation.values()))])
        fig3.update_layout(title='Election Participation', xaxis_title='Election', yaxis_title='Number of Voters')
        graph3 = opy.plot(fig3, auto_open=False, output_type='div')
        context['election_participation_bar_chart'] = graph3

        context['party_affiliations'] = Voter.objects.values_list('party_affiliation', flat=True).distinct()
        context['years'] = range(1910, 2007)
        context['voter_scores'] = range(6)

        return context
    