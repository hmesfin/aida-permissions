from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.contrib.auth import get_user_model
from .compat import _
from .models import Permission, PermissionCategory, Role, RolePermission, UserRole

User = get_user_model()


@admin.register(PermissionCategory)
class PermissionCategoryAdmin(admin.ModelAdmin):
    list_display = ['display_name', 'name', 'order', 'is_active', 'permission_count']
    list_filter = ['is_active']
    search_fields = ['name', 'display_name', 'description']
    ordering = ['order', 'name']
    
    def permission_count(self, obj):
        count = obj.permissions.count()
        url = reverse('admin:aida_permissions_permission_changelist') + f'?category__id__exact={obj.id}'
        return format_html('<a href="{}">{} permissions</a>', url, count)
    permission_count.short_description = _('Permissions')


class RolePermissionInline(admin.TabularInline):
    model = RolePermission
    extra = 1
    autocomplete_fields = ['permission']
    fields = ['permission', 'is_active', 'expires_at', 'conditions']
    readonly_fields = ['granted_at']


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['codename', 'name', 'category', 'resource', 'permission_type', 'is_active', 'is_system']
    list_filter = ['category', 'permission_type', 'is_active', 'is_system', 'requires_object']
    search_fields = ['codename', 'name', 'description', 'resource']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'updated_by']
    autocomplete_fields = ['category']
    ordering = ['category', 'resource', 'permission_type']
    
    fieldsets = (
        (None, {
            'fields': ('codename', 'name', 'description', 'category')
        }),
        (_('Permission Details'), {
            'fields': ('permission_type', 'resource', 'requires_object', 'is_active', 'is_system')
        }),
        (_('Metadata'), {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        (_('Audit'), {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',)
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
    list_display = ['display_name', 'name', 'role_type', 'priority', 'is_active', 'is_default', 'user_count', 'permission_count']
    list_filter = ['role_type', 'is_active', 'is_default']
    search_fields = ['name', 'display_name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'updated_by']
    inlines = [RolePermissionInline]
    ordering = ['-priority', 'name']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'display_name', 'description')
        }),
        (_('Role Configuration'), {
            'fields': ('role_type', 'parent_role', 'priority', 'is_active', 'is_default', 'max_users')
        }),
        (_('Metadata'), {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        (_('Audit'), {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    def user_count(self, obj):
        count = obj.user_assignments.filter(is_active=True).count()
        url = reverse('admin:aida_permissions_userrole_changelist') + f'?role__id__exact={obj.id}'
        return format_html('<a href="{}">{} users</a>', url, count)
    user_count.short_description = _('Users')
    
    def permission_count(self, obj):
        count = obj.permissions.filter(rolepermission__is_active=True).distinct().count()
        return f"{count} permissions"
    permission_count.short_description = _('Active Permissions')
    
    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
    
    def has_delete_permission(self, request, obj=None):
        if obj and obj.role_type == 'system':
            return False
        return super().has_delete_permission(request, obj)
    
    actions = ['clone_role', 'activate_roles', 'deactivate_roles']
    
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
    list_display = ['user', 'role', 'is_active', 'assigned_at', 'expires_at', 'assigned_by']
    list_filter = ['is_active', 'role', 'assigned_at', 'expires_at']
    search_fields = ['user__username', 'user__email', 'role__name', 'role__display_name']
    autocomplete_fields = ['user', 'role', 'assigned_by']
    readonly_fields = ['assigned_at']
    date_hierarchy = 'assigned_at'
    
    fieldsets = (
        (None, {
            'fields': ('user', 'role', 'is_active')
        }),
        (_('Assignment Details'), {
            'fields': ('assigned_at', 'assigned_by', 'expires_at')
        }),
        (_('Scope'), {
            'fields': ('scope',),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not change:
            obj.assigned_by = request.user
        super().save_model(request, obj, form, change)
    
    actions = ['activate_assignments', 'deactivate_assignments', 'extend_expiration']
    
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