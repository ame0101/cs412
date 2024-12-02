from django.urls import path
from . import views

urlpatterns = [
    path('main/', views.main_view, name='main'),
    path('order/', views.order_view, name='order'),  
    path('confirmation/', views.confirmation, name='confirmation'),
    path('', views.main_view, name='home'), 
]