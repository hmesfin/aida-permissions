from django.urls import path, include

urlpatterns = [
    path('api/', include('aida_permissions.urls')),
]