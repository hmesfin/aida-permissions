from django.urls import include, path

urlpatterns = [
    path("api/", include("aida_permissions.urls")),
]
