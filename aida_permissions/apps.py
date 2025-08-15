from django.apps import AppConfig


class AidaPermissionsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'aida_permissions'
    verbose_name = 'AIDA Permissions'

    def ready(self):
        import aida_permissions.signals