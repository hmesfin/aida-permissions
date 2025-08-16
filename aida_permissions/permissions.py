from rest_framework import permissions

from .utils import PermissionChecker


class AidaPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        permission_required = getattr(view, "permission_required", {})

        if not permission_required:
            return True

        action = view.action if hasattr(view, "action") else None

        if not action:
            method_map = {
                "GET": "list" if not view.kwargs.get("pk") else "retrieve",
                "POST": "create",
                "PUT": "update",
                "PATCH": "partial_update",
                "DELETE": "destroy",
            }
            action = method_map.get(request.method, None)

        if not action or action not in permission_required:
            return True

        required_permission = permission_required[action]

        if isinstance(required_permission, (list, tuple)):
            permissions_to_check = required_permission
        else:
            permissions_to_check = [required_permission]

        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))

        return any(checker.has_permission(permission) for permission in permissions_to_check)

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        object_permission_required = getattr(view, "object_permission_required", {})

        if not object_permission_required:
            return True

        action = view.action if hasattr(view, "action") else None

        if not action:
            method_map = {
                "GET": "retrieve",
                "PUT": "update",
                "PATCH": "partial_update",
                "DELETE": "destroy",
            }
            action = method_map.get(request.method, None)

        if not action or action not in object_permission_required:
            return True

        required_permission = object_permission_required[action]

        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))
        return checker.has_object_permission(required_permission, obj)


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        owner_field = getattr(view, "owner_field", "owner")

        if hasattr(obj, owner_field):
            owner = getattr(obj, owner_field)
            return owner == request.user

        if hasattr(obj, "created_by"):
            return obj.created_by == request.user

        return False


class HasRolePermission(permissions.BasePermission):
    def __init__(self, required_roles=None):
        self.required_roles = required_roles or []

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        required_roles = self.required_roles or getattr(view, "required_roles", [])

        if not required_roles:
            return True

        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))
        role_names = checker.get_role_names()

        return any(role in role_names for role in required_roles)
