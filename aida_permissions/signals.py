from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.core.cache import cache
from .models import Role, UserRole, RolePermission, Permission

User = get_user_model()


@receiver(post_save, sender=UserRole)
def clear_user_permission_cache(sender, instance, created, **kwargs):
    cache.delete(f'user_roles:{instance.user_id}')
    cache.delete(f'user_permissions:{instance.user_id}')
    
    for tenant_id in [None, getattr(instance, 'tenant_id', None)]:
        if tenant_id:
            cache.delete(f'user_roles:{instance.user_id}:{tenant_id}')
            cache.delete(f'user_permissions:{instance.user_id}:{tenant_id}')


@receiver(post_delete, sender=UserRole)
def clear_user_permission_cache_on_delete(sender, instance, **kwargs):
    clear_user_permission_cache(sender, instance, created=False, **kwargs)


@receiver(post_save, sender=RolePermission)
def clear_role_cache(sender, instance, created, **kwargs):
    cache.delete_pattern(f'role:{instance.role_id}:*')
    
    user_roles = UserRole.objects.filter(role_id=instance.role_id, is_active=True)
    for user_role in user_roles:
        cache.delete(f'user_permissions:{user_role.user_id}')
        if hasattr(user_role, 'tenant_id') and user_role.tenant_id:
            cache.delete(f'user_permissions:{user_role.user_id}:{user_role.tenant_id}')


@receiver(post_delete, sender=RolePermission)
def clear_role_cache_on_delete(sender, instance, **kwargs):
    clear_role_cache(sender, instance, created=False, **kwargs)


@receiver(post_save, sender=Role)
def handle_default_role(sender, instance, created, **kwargs):
    if instance.is_default and instance.is_active:
        Role.objects.filter(
            is_default=True,
            tenant_id=instance.tenant_id
        ).exclude(pk=instance.pk).update(is_default=False)


@receiver(post_save, sender=User)
def assign_default_roles(sender, instance, created, **kwargs):
    if created:
        tenant_id = getattr(instance, 'tenant_id', None)
        default_roles = Role.objects.filter(is_default=True, is_active=True)
        
        if tenant_id:
            default_roles = default_roles.filter(tenant_id=tenant_id)
        
        for role in default_roles:
            UserRole.objects.get_or_create(
                user=instance,
                role=role,
                defaults={
                    'is_active': True,
                    'tenant_id': tenant_id
                }
            )


@receiver(pre_save, sender=Permission)
def validate_system_permission(sender, instance, **kwargs):
    if instance.pk:
        try:
            existing = Permission.objects.get(pk=instance.pk)
            if existing.is_system and not instance.is_system:
                raise ValueError("Cannot remove system flag from existing permission")
        except Permission.DoesNotExist:
            pass