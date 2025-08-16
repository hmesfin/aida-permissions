from django.core.cache import cache
from django.db import models

from ..compat import JSONField, _, cache_delete_pattern
from .base import TenantAwareModel


class PermissionCategory(TenantAwareModel):
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True)
    order = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _("Permission Category")
        verbose_name_plural = _("Permission Categories")
        ordering = ["order", "name"]

    def __str__(self):
        return self.display_name


class Permission(TenantAwareModel):
    PERMISSION_TYPES = (
        ("view", _("View")),
        ("create", _("Create")),
        ("edit", _("Edit")),
        ("delete", _("Delete")),
        ("export", _("Export")),
        ("import", _("Import")),
        ("approve", _("Approve")),
        ("reject", _("Reject")),
        ("custom", _("Custom")),
    )

    codename = models.CharField(
        max_length=255,
        unique=True,
        help_text=_('Unique identifier for the permission (e.g., "equipment.view")'),
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.ForeignKey(
        PermissionCategory,
        on_delete=models.CASCADE,
        related_name="permissions",
    )
    permission_type = models.CharField(
        max_length=20,
        choices=PERMISSION_TYPES,
        default="custom",
    )
    resource = models.CharField(
        max_length=100,
        help_text=_('Resource this permission applies to (e.g., "equipment", "rental")'),
    )
    is_active = models.BooleanField(default=True)
    is_system = models.BooleanField(
        default=False,
        help_text=_("System permissions cannot be deleted"),
    )
    requires_object = models.BooleanField(
        default=False,
        help_text=_("Whether this permission requires object-level checking"),
    )
    metadata = JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")
        ordering = ["category", "resource", "permission_type"]
        indexes = [
            models.Index(fields=["codename"]),
            models.Index(fields=["resource", "permission_type"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.codename})"

    def save(self, *args, **kwargs):
        if not self.codename and self.resource and self.permission_type != "custom":
            self.codename = f"{self.resource}.{self.permission_type}"

        super().save(*args, **kwargs)
        self.clear_cache()

    def delete(self, *args, **kwargs):
        if self.is_system:
            raise ValueError(_("System permissions cannot be deleted"))
        super().delete(*args, **kwargs)
        self.clear_cache()

    def clear_cache(self):
        cache_delete_pattern("permission:*")
        cache_delete_pattern("user_permissions:*")

    @classmethod
    def get_by_codename(cls, codename, tenant_id=None):
        cache_key = f"permission:{codename}:{tenant_id}"
        permission = cache.get(cache_key)

        if permission is None:
            filters = {"codename": codename, "is_active": True}
            if tenant_id:
                filters["tenant_id"] = tenant_id

            try:
                permission = cls.objects.get(**filters)
                cache.set(cache_key, permission, 3600)
            except cls.DoesNotExist:
                return None

        return permission

    @classmethod
    def bulk_create_permissions(cls, permissions_data, category, tenant_id=None):
        permissions = []
        for perm_data in permissions_data:
            perm_data["category"] = category
            if tenant_id:
                perm_data["tenant_id"] = tenant_id
            permissions.append(cls(**perm_data))

        return cls.objects.bulk_create(permissions, ignore_conflicts=True)
