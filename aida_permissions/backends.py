from django.contrib.auth.backends import ModelBackend
from django.core.cache import cache
from .utils import PermissionChecker


class AidaPermissionBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        return super().authenticate(request, username, password, **kwargs)
    
    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active:
            return False
        
        if user_obj.is_superuser:
            return True
        
        tenant_id = getattr(user_obj, 'tenant_id', None)
        checker = PermissionChecker(user_obj, tenant_id)
        
        if obj is None:
            return checker.has_permission(perm)
        else:
            return checker.has_object_permission(perm, obj)
    
    def has_module_perms(self, user_obj, app_label):
        if not user_obj.is_active:
            return False
        
        if user_obj.is_superuser:
            return True
        
        tenant_id = getattr(user_obj, 'tenant_id', None)
        checker = PermissionChecker(user_obj, tenant_id)
        permissions = checker.get_user_permissions()
        
        return any(perm.startswith(f"{app_label}.") for perm in permissions)
    
    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active:
            return set()
        
        if user_obj.is_superuser:
            from .models import Permission
            return set(Permission.objects.values_list('codename', flat=True))
        
        tenant_id = getattr(user_obj, 'tenant_id', None)
        checker = PermissionChecker(user_obj, tenant_id)
        return set(checker.get_user_permissions())
    
    def get_user_permissions(self, user_obj, obj=None):
        return self.get_all_permissions(user_obj, obj)
    
    def get_group_permissions(self, user_obj, obj=None):
        return set()