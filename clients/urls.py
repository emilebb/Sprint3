from django.urls import path
from . import views

urlpatterns = [
    path("", views.clients_list, name="clients_list"),              # GET (Admin)
    path("<int:pk>/", views.client_detail, name="client_detail"),   # GET (Admin)
    path("create/", views.client_create, name="client_create"),     # POST (Admin)
    path("<int:pk>/update/", views.client_update, name="client_update"),  # POST/PUT/PATCH (Admin)
    path("<int:pk>/delete/", views.client_delete, name="client_delete"),  # DELETE (Admin)

    path("security/report/", views.security_report, name="security_report"),  # GET (Admin)
]