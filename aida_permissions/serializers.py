from typing import ClassVar

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Permission, PermissionCategory, Role, RolePermission, UserRole

User = get_user_model()


class PermissionCategorySerializer(serializers.ModelSerializer):
    permission_count = serializers.SerializerMethodField()

    class Meta:
        model = PermissionCategory
        fields: ClassVar = [
            "id", "name", "display_name", "description", "icon",
            "order", "is_active", "permission_count", "created_at", "updated_at",
        ]
        read_only_fields: ClassVar = ["id", "created_at", "updated_at"]

    def get_permission_count(self, obj):
        return obj.permissions.filter(is_active=True).count()


class PermissionSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source="category.name", read_only=True)
    category_display = serializers.CharField(source="category.display_name", read_only=True)

    class Meta:
        model = Permission
        fields: ClassVar = [
            "id", "codename", "name", "description", "category", "category_name",
            "category_display", "permission_type", "resource", "is_active",
            "is_system", "requires_object", "metadata", "created_at", "updated_at",
        ]
        read_only_fields: ClassVar = ["id", "created_at", "updated_at", "is_system"]

    def validate_codename(self, value):
        if self.instance and self.instance.is_system:
            raise serializers.ValidationError("System permissions cannot be modified")
        return value


class RolePermissionSerializer(serializers.ModelSerializer):
    permission_detail = PermissionSerializer(source="permission", read_only=True)

    class Meta:
        model = RolePermission
        fields: ClassVar = [
            "id", "role", "permission", "permission_detail", "is_active",
            "granted_at", "expires_at", "conditions",
        ]
        read_only_fields: ClassVar = ["id", "granted_at"]


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)
    permission_count = serializers.SerializerMethodField()
    user_count = serializers.SerializerMethodField()
    parent_role_name = serializers.CharField(source="parent_role.name", read_only=True)
    all_permissions = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields: ClassVar = [
            "id", "name", "display_name", "description", "role_type",
            "is_active", "is_default", "priority", "permissions",
            "permission_count", "user_count", "parent_role", "parent_role_name",
            "metadata", "max_users", "created_at", "updated_at", "all_permissions",
        ]
        read_only_fields: ClassVar = ["id", "created_at", "updated_at"]

    def get_permission_count(self, obj):
        return obj.permissions.filter(rolepermission__is_active=True).distinct().count()

    def get_user_count(self, obj):
        return obj.user_assignments.filter(is_active=True).count()

    def get_all_permissions(self, obj):
        permissions = obj.get_all_permissions(include_inherited=True)
        return PermissionSerializer(permissions, many=True).data

    def validate(self, data):
        if self.instance and self.instance.role_type == "system":
            if "role_type" in data and data["role_type"] != "system":
                raise serializers.ValidationError("Cannot change system role type")
        return data


class UserRoleSerializer(serializers.ModelSerializer):
    role_detail = RoleSerializer(source="role", read_only=True)
    user_detail = serializers.SerializerMethodField()
    assigned_by_name = serializers.CharField(source="assigned_by.get_full_name", read_only=True)
    is_valid = serializers.SerializerMethodField()

    class Meta:
        model = UserRole
        fields: ClassVar = [
            "id", "user", "user_detail", "role", "role_detail", "is_active",
            "assigned_at", "assigned_by", "assigned_by_name", "expires_at",
            "scope", "is_valid",
        ]
        read_only_fields: ClassVar = ["id", "assigned_at"]

    def get_user_detail(self, obj):
        return {
            "id": obj.user.id,
            "username": obj.user.username,
            "email": getattr(obj.user, "email", ""),
            "full_name": obj.user.get_full_name() if hasattr(obj.user, "get_full_name") else str(obj.user),
        }

    def get_is_valid(self, obj):
        return obj.is_valid()

    def validate(self, data):
        role = data.get("role") or self.instance.role if self.instance else None
        data.get("user") or self.instance.user if self.instance else None

        if role and role.max_users:
            current_count = UserRole.objects.filter(
                role=role,
                is_active=True,
            ).exclude(pk=self.instance.pk if self.instance else None).count()

            if current_count >= role.max_users:
                raise serializers.ValidationError(
                    f"Role {role.name} has reached maximum user limit ({role.max_users})",
                )

        return data


class AssignRoleSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()
    role_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    scope = serializers.JSONField(required=False, default=dict)

    def validate_user_id(self, value):
        try:
            User.objects.get(pk=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
        return value

    def validate_role_id(self, value):
        try:
            Role.objects.get(pk=value)
        except Role.DoesNotExist:
            raise serializers.ValidationError("Role not found")
        return value


class BulkAssignRoleSerializer(serializers.Serializer):
    user_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
    )
    role_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    scope = serializers.JSONField(required=False, default=dict)

    def validate_user_ids(self, value):
        existing_ids = set(User.objects.filter(pk__in=value).values_list("pk", flat=True))
        invalid_ids = set(value) - existing_ids
        if invalid_ids:
            raise serializers.ValidationError(f"Users not found: {invalid_ids}")
        return value

    def validate_role_id(self, value):
        try:
            Role.objects.get(pk=value)
        except Role.DoesNotExist:
            raise serializers.ValidationError("Role not found")
        return value


class UserPermissionsSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=False)
    permissions = serializers.ListField(child=serializers.CharField())
    roles = serializers.ListField(child=serializers.DictField())

    class Meta:
        fields: ClassVar = ["user_id", "permissions", "roles"]
