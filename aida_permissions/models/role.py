from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import models

from ..compat import JSONField, _, cache_delete_pattern
from .base import TenantAwareModel
from .permission import Permission

User = get_user_model()


class Role(TenantAwareModel):
    ROLE_TYPES = (
        ("system", _("System")),
        ("custom", _("Custom")),
        ("template", _("Template")),
    )

    name = models.CharField(max_length=100)
    display_name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    role_type = models.CharField(
        max_length=20,
        choices=ROLE_TYPES,
        default="custom",
    )
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(
        default=False,
        help_text=_("Automatically assigned to new users"),
    )
    priority = models.IntegerField(
        default=0,
        help_text=_("Higher priority roles override lower ones"),
    )
    permissions = models.ManyToManyField(
        Permission,
        through="RolePermission",
        related_name="roles",
    )
    parent_role = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="child_roles",
        help_text=_("Inherit permissions from parent role"),
    )
    metadata = JSONField(default=dict, blank=True)
    max_users = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("Maximum number of users that can have this role"),
    )

    class Meta:
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
        ordering = ["-priority", "name"]
        unique_together = [["name", "tenant_id"]]
        indexes = [
            models.Index(fields=["is_active", "is_default"]),
            models.Index(fields=["tenant_id", "name"]),
        ]

    def __str__(self):
        return self.display_name or self.name

    def save(self, *args, **kwargs):
        if self.is_default:
            Role.objects.filter(
                tenant_id=self.tenant_id,
                is_default=True,
            ).exclude(pk=self.pk).update(is_default=False)

        super().save(*args, **kwargs)
        self.clear_cache()

    def delete(self, *args, **kwargs):
        if self.role_type == "system":
            raise ValueError(_("System roles cannot be deleted"))
        super().delete(*args, **kwargs)
        self.clear_cache()

    def clear_cache(self):
        cache_delete_pattern(f"role:{self.id}:*")
        cache_delete_pattern("user_roles:*")
        cache_delete_pattern("user_permissions:*")

    def get_all_permissions(self, include_inherited=True):
        cache_key = f"role:{self.id}:permissions:{include_inherited}"
        permissions = cache.get(cache_key)

        if permissions is None:
            permission_ids = set()

            permission_ids.update(
                self.rolepermission_set.filter(is_active=True)
                .values_list("permission_id", flat=True),
            )

            if include_inherited and self.parent_role:
                parent_permissions = self.parent_role.get_all_permissions(include_inherited=True)
                permission_ids.update([p.id for p in parent_permissions])

            permissions = Permission.objects.filter(
                id__in=permission_ids,
                is_active=True,
            )

            cache.set(cache_key, list(permissions), 3600)

        return permissions

    def has_permission(self, permission_codename):
        permissions = self.get_all_permissions()
        return any(p.codename == permission_codename for p in permissions)

    def add_permission(self, permission, **kwargs):
        role_permission, created = RolePermission.objects.get_or_create(
            role=self,
            permission=permission,
            defaults=kwargs,
        )
        self.clear_cache()
        return role_permission

    def remove_permission(self, permission):
        RolePermission.objects.filter(
            role=self,
            permission=permission,
        ).delete()
        self.clear_cache()

    def clone(self, new_name, new_display_name=None):
        cloned_role = Role.objects.create(
            name=new_name,
            display_name=new_display_name or f"Copy of {self.display_name}",
            description=self.description,
            role_type="custom",
            parent_role=self.parent_role,
            tenant_id=self.tenant_id,
            metadata=self.metadata.copy() if self.metadata else {},
        )

        for role_perm in self.rolepermission_set.all():
            RolePermission.objects.create(
                role=cloned_role,
                permission=role_perm.permission,
                is_active=role_perm.is_active,
                conditions=role_perm.conditions,
            )

        return cloned_role


class RolePermission(TenantAwareModel):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    conditions = JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional conditions for this permission grant"),
    )

    class Meta:
        verbose_name = _("Role Permission")
        verbose_name_plural = _("Role Permissions")
        unique_together = [["role", "permission"]]
        indexes = [
            models.Index(fields=["role", "permission", "is_active"]),
        ]

    def __str__(self):
        return f"{self.role.name} - {self.permission.codename}"

    def is_valid(self):
        from django.utils import timezone
        if not self.is_active:
            return False
        return not (self.expires_at and self.expires_at < timezone.now())


class UserRole(TenantAwareModel):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_roles",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="user_assignments",
    )
    is_active = models.BooleanField(default=True)
    assigned_at = models.DateTimeField(auto_now_add=True)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="role_assignments_made",
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    scope = JSONField(
        default=dict,
        blank=True,
        help_text=_("Scope limitations for this role assignment"),
    )

    class Meta:
        verbose_name = _("User Role")
        verbose_name_plural = _("User Roles")
        unique_together = [["user", "role", "tenant_id"]]
        ordering = ["-assigned_at"]
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["role", "is_active"]),
        ]

    def __str__(self):
        return f"{self.user} - {self.role.name}"

    def save(self, *args, **kwargs):
        if self.role.max_users:
            current_count = UserRole.objects.filter(
                role=self.role,
                is_active=True,
            ).exclude(pk=self.pk).count()

            if current_count >= self.role.max_users:
                raise ValueError(
                    f"Role {self.role.name} has reached maximum user limit ({self.role.max_users})",
                )

        super().save(*args, **kwargs)
        self.clear_user_cache()

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        self.clear_user_cache()

    def clear_user_cache(self):
        cache.delete(f"user_roles:{self.user_id}")
        cache.delete(f"user_permissions:{self.user_id}")

    def is_valid(self):
        from django.utils import timezone
        if not self.is_active:
            return False
        return not (self.expires_at and self.expires_at < timezone.now())
