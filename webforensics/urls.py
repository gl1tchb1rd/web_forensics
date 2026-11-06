from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("healthz", views.health),
    path("api/plan", views.plan),
    path("api/analyze", views.analyze),
    path("api/report.pdf", views.download_pdf),
]
