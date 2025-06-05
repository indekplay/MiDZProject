from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('upload/', views.upload_file, name='upload'),
    path('ip-list/', views.ip_list, name='ip_list'),
    path('chart/', views.chart, name='chart'),
    path('botnet/', views.botnet, name='botnet'),
    path('analiza/', views.analiza, name='analiza'),
]