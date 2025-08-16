from typing import ClassVar

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.html import format_html

from .compat import _
from .models import Permission, PermissionCategory, Role, RolePermission, UserRole
from .utils.user_utils import get_user_search_fields

User = get_user_model()


@admin.register(PermissionCategory)
class PermissionCategoryAdmin(admin.ModelAdmin):
    list_display: ClassVar = ["display_name", "name", "order", "is_active", "permission_count"]
    list_filter: ClassVar = ["is_active"]
    search_fields: ClassVar = ["name", "display_name", "description"]
    ordering: ClassVar = ["order", "name"]

    def permission_count(self, obj):
        count = obj.permissions.count()
        url = reverse("admin:aida_permissions_permission_changelist") + f"?category__id__exact={obj.id}"
        return format_html('<a href="{}">{} permissions</a>', url, count)
    permission_count.short_description = _("Permissions")


class RolePermissionInline(admin.TabularInline):
    model: ClassVar = RolePermission
    extra: ClassVar = 1
    autocomplete_fields: ClassVar = ["permission"]
    fields: ClassVar = ["permission", "is_active", "expires_at", "conditions"]
    readonly_fields: ClassVar = ["granted_at"]


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display: ClassVar = ["codename", "name", "category", "resource", "permission_type", "is_active", "is_system"]
    list_filter: ClassVar = ["category", "permission_type", "is_active", "is_system", "requires_object"]
    search_fields: ClassVar = ["codename", "name", "description", "resource"]
    readonly_fields: ClassVar = ["created_at", "updated_at", "created_by", "updated_by"]
    autocomplete_fields: ClassVar = ["category"]
    ordering: ClassVar = ["category", "resource", "permission_type"]

    fieldsets: ClassVar = (
        (None, {
            "fields": ("codename", "name", "description", "category"),
        }),
        (_("Permission Details"), {
            "fields": ("permission_type", "resource", "requires_object", "is_active", "is_system"),
        }),
        (_("Metadata"), {
            "fields": ("metadata",),
            "classes": ("collapse",),
        }),
        (_("Audit"), {
            "fields": ("created_at", "updated_at", "created_by", "updated_by"),
            "classes": ("collapse",),
        }),
    )

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)

    def has_delete_permission(self, request, obj=None):
        if obj and obj.is_system:
            return False
        return super().has_delete_permission(request, obj)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display: ClassVar = ["display_name", "name", "role_type", "priority", "is_active", "is_default", "user_count", "permission_count"]
    list_filter: ClassVar = ["role_type", "is_active", "is_default"]
    search_fields: ClassVar = ["name", "display_name", "description"]
    readonly_fields: ClassVar = ["created_at", "updated_at", "created_by", "updated_by"]
    inlines: ClassVar = [RolePermissionInline]
    ordering: ClassVar = ["-priority", "name"]

    fieldsets: ClassVar = (
        (None, {
            "fields": ("name", "display_name", "description"),
        }),
        (_("Role Configuration"), {
            "fields": ("role_type", "parent_role", "priority", "is_active", "is_default", "max_users"),
        }),
        (_("Metadata"), {
            "fields": ("metadata",),
            "classes": ("collapse",),
        }),
        (_("Audit"), {
            "fields": ("created_at", "updated_at", "created_by", "updated_by"),
            "classes": ("collapse",),
        }),
    )

    def user_count(self, obj):
        count = obj.user_assignments.filter(is_active=True).count()
        url = reverse("admin:aida_permissions_userrole_changelist") + f"?role__id__exact={obj.id}"
        return format_html('<a href="{}">{} users</a>', url, count)
    user_count.short_description = _("Users")

    def permission_count(self, obj):
        count = obj.permissions.filter(rolepermission__is_active=True).distinct().count()
        return f"{count} permissions"
    permission_count.short_description = _("Active Permissions")

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)

    def has_delete_permission(self, request, obj=None):
        if obj and obj.role_type == "system":
            return False
        return super().has_delete_permission(request, obj)

    actions: ClassVar = ["clone_role", "activate_roles", "deactivate_roles"]

    def clone_role(self, request, queryset):
        for role in queryset:
            role.clone(f"{role.name}_copy", f"Copy of {role.display_name}")
        self.message_user(request, f"{queryset.count()} role(s) cloned successfully.")
    clone_role.short_description = _("Clone selected roles")

    def activate_roles(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} role(s) activated.")
    activate_roles.short_description = _("Activate selected roles")

    def deactivate_roles(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} role(s) deactivated.")
    deactivate_roles.short_description = _("Deactivate selected roles")


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display: ClassVar = ["user", "role", "is_active", "assigned_at", "expires_at", "assigned_by"]
    list_filter: ClassVar = ["is_active", "role", "assigned_at", "expires_at"]
    autocomplete_fields: ClassVar = ["user", "role", "assigned_by"]
    readonly_fields: ClassVar = ["assigned_at"]
    date_hierarchy: ClassVar = "assigned_at"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically set search_fields based on User model
        self.search_fields = get_user_search_fields()

    fieldsets: ClassVar = (
        (None, {
            "fields": ("user", "role", "is_active"),
        }),
        (_("Assignment Details"), {
            "fields": ("assigned_at", "assigned_by", "expires_at"),
        }),
        (_("Scope"), {
            "fields": ("scope",),
            "classes": ("collapse",),
        }),
    )

    def save_model(self, request, obj, form, change):
        if not change:
            obj.assigned_by = request.user
        super().save_model(request, obj, form, change)

    actions: ClassVar = ["activate_assignments", "deactivate_assignments", "extend_expiration"]

    def activate_assignments(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} assignment(s) activated.")
    activate_assignments.short_description = _("Activate selected assignments")

    def deactivate_assignments(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} assignment(s) deactivated.")
    deactivate_assignments.short_description = _("Deactivate selected assignments")

    def extend_expiration(self, request, queryset):
        from datetime import timedelta

        from django.utils import timezone

        new_expiry = timezone.now() + timedelta(days=30)
        queryset.update(expires_at=new_expiry)
        self.message_user(request, f"Extended expiration for {queryset.count()} assignment(s) by 30 days.")
    extend_expiration.short_description = _("Extend expiration by 30 days")
