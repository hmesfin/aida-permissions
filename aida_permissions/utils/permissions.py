from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from ..models import Permission, UserRole


class PermissionChecker:
    def __init__(self, user, tenant_id=None):
        self.user = user
        self.tenant_id = tenant_id
        self._permissions_cache = None
        self._roles_cache = None
    
    def set_tenant(self, tenant_id):
        self.tenant_id = tenant_id
        self._permissions_cache = None
        self._roles_cache = None
    
    def get_user_roles(self):
        if self._roles_cache is not None:
            return self._roles_cache
        
        cache_key = f'user_roles:{self.user.id}:{self.tenant_id}'
        roles = cache.get(cache_key)
        
        if roles is None:
            user_roles = UserRole.objects.filter(
                user=self.user,
                is_active=True
            ).select_related('role')
            
            if self.tenant_id:
                user_roles = user_roles.filter(
                    Q(tenant_id=self.tenant_id) | Q(tenant_id__isnull=True)
                )
            
            now = timezone.now()
            roles = []
            for user_role in user_roles:
                if user_role.expires_at is None or user_role.expires_at > now:
                    roles.append(user_role.role)
            
            cache.set(cache_key, roles, 3600)
        
        self._roles_cache = roles
        return roles
    
    def get_user_permissions(self):
        if self._permissions_cache is not None:
            return self._permissions_cache
        
        cache_key = f'user_permissions:{self.user.id}:{self.tenant_id}'
        permissions = cache.get(cache_key)
        
        if permissions is None:
            permission_set = set()
            roles = self.get_user_roles()
            
            for role in roles:
                if role.is_active:
                    role_permissions = role.get_all_permissions(include_inherited=True)
                    permission_set.update([p.codename for p in role_permissions])
            
            permissions = list(permission_set)
            cache.set(cache_key, permissions, 3600)
        
        self._permissions_cache = permissions
        return permissions
    
    def has_permission(self, permission_codename):
        if self.user.is_superuser:
            return True
        
        permissions = self.get_user_permissions()
        
        if permission_codename in permissions:
            return True
        
        parts = permission_codename.split('.')
        if len(parts) == 2:
            resource, action = parts
            if f"{resource}.*" in permissions or f"*.{action}" in permissions or "*.*" in permissions:
                return True
        
        return False
    
    def has_any_permission(self, permission_codenames):
        return any(self.has_permission(perm) for perm in permission_codenames)
    
    def has_all_permissions(self, permission_codenames):
        return all(self.has_permission(perm) for perm in permission_codenames)
    
    def has_object_permission(self, permission_codename, obj=None):
        if not self.has_permission(permission_codename):
            return False
        
        if obj is None:
            return True
        
        permission = Permission.get_by_codename(permission_codename, self.tenant_id)
        if not permission or not permission.requires_object:
            return True
        
        if hasattr(obj, 'check_permission'):
            return obj.check_permission(self.user, permission_codename)
        
        if hasattr(obj, 'created_by') and obj.created_by == self.user:
            return True
        
        if hasattr(obj, 'owner') and obj.owner == self.user:
            return True
        
        if hasattr(obj, 'tenant_id') and self.tenant_id:
            if obj.tenant_id != self.tenant_id:
                return False
        
        return True
    
    def filter_queryset(self, queryset, permission_codename):
        if self.user.is_superuser:
            return queryset
        
        if not self.has_permission(permission_codename):
            return queryset.none()
        
        permission = Permission.get_by_codename(permission_codename, self.tenant_id)
        if not permission or not permission.requires_object:
            return queryset
        
        filters = Q()
        
        if hasattr(queryset.model, 'created_by'):
            filters |= Q(created_by=self.user)
        
        if hasattr(queryset.model, 'owner'):
            filters |= Q(owner=self.user)
        
        if hasattr(queryset.model, 'tenant_id') and self.tenant_id:
            filters &= Q(tenant_id=self.tenant_id)
        
        if filters:
            return queryset.filter(filters)
        
        return queryset
    
    def get_role_names(self):
        roles = self.get_user_roles()
        return [role.name for role in roles]
    
    def has_role(self, role_name):
        return role_name in self.get_role_names()
    
    def clear_cache(self):
        cache.delete(f'user_roles:{self.user.id}:{self.tenant_id}')
        cache.delete(f'user_permissions:{self.user.id}:{self.tenant_id}')
        self._permissions_cache = None
        self._roles_cache = None


def has_permission(user, permission_codename, tenant_id=None):
    checker = PermissionChecker(user, tenant_id)
    return checker.has_permission(permission_codename)


def get_user_permissions(user, tenant_id=None):
    checker = PermissionChecker(user, tenant_id)
    return checker.get_user_permissions()