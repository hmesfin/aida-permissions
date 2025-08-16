from typing import ClassVar

from django.contrib.auth import get_user_model
from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Permission, PermissionCategory, Role, UserRole
from .permissions import AidaPermission
from .serializers import (
    AssignRoleSerializer,
    BulkAssignRoleSerializer,
    PermissionCategorySerializer,
    PermissionSerializer,
    RolePermissionSerializer,
    RoleSerializer,
    UserRoleSerializer,
)
from .utils import PermissionChecker
from .utils.user_utils import get_user_search_fields

User = get_user_model()


class PermissionCategoryViewSet(viewsets.ModelViewSet):
    queryset: ClassVar = PermissionCategory.objects.all()
    serializer_class: ClassVar = PermissionCategorySerializer
    permission_classes: ClassVar = [IsAuthenticated, AidaPermission]
    filter_backends: ClassVar = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields: ClassVar = ["is_active"]
    search_fields: ClassVar = ["name", "display_name", "description"]
    ordering_fields: ClassVar = ["order", "name", "created_at"]
    ordering: ClassVar = ["order", "name"]

    permission_required: ClassVar = {
        "list": "permissions.view_category",
        "retrieve": "permissions.view_category",
        "create": "permissions.create_category",
        "update": "permissions.edit_category",
        "partial_update": "permissions.edit_category",
        "destroy": "permissions.delete_category",
    }


class PermissionViewSet(viewsets.ModelViewSet):
    queryset: ClassVar = Permission.objects.all()
    serializer_class: ClassVar = PermissionSerializer
    permission_classes: ClassVar = [IsAuthenticated, AidaPermission]
    filter_backends: ClassVar = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields: ClassVar = ["category", "permission_type", "resource", "is_active", "is_system", "requires_object"]
    search_fields: ClassVar = ["codename", "name", "description", "resource"]
    ordering_fields: ClassVar = ["codename", "name", "resource", "created_at"]
    ordering: ClassVar = ["category", "resource", "permission_type"]

    permission_required: ClassVar = {
        "list": "permissions.view",
        "retrieve": "permissions.view",
        "create": "permissions.create",
        "update": "permissions.edit",
        "partial_update": "permissions.edit",
        "destroy": "permissions.delete",
    }

    def destroy(self, request, *args, **kwargs):
        permission = self.get_object()
        if permission.is_system:
            return Response(
                {"error": "System permissions cannot be deleted"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=False, methods=["get"])
    def by_resource(self, request):
        resource = request.query_params.get("resource")
        if not resource:
            return Response(
                {"error": "Resource parameter is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        permissions = self.get_queryset().filter(resource=resource, is_active=True)
        serializer = self.get_serializer(permissions, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def my_permissions(self, request):
        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))
        permissions = checker.get_user_permissions()
        return Response({"permissions": permissions})


class RoleViewSet(viewsets.ModelViewSet):
    queryset: ClassVar = Role.objects.all()
    serializer_class: ClassVar = RoleSerializer
    permission_classes: ClassVar = [IsAuthenticated, AidaPermission]
    filter_backends: ClassVar = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields: ClassVar = ["role_type", "is_active", "is_default"]
    search_fields: ClassVar = ["name", "display_name", "description"]
    ordering_fields: ClassVar = ["priority", "name", "created_at"]
    ordering: ClassVar = ["-priority", "name"]

    permission_required: ClassVar = {
        "list": "roles.view",
        "retrieve": "roles.view",
        "create": "roles.create",
        "update": "roles.edit",
        "partial_update": "roles.edit",
        "destroy": "roles.delete",
        "clone": "roles.create",
        "assign_permissions": "roles.edit",
        "remove_permissions": "roles.edit",
    }

    def destroy(self, request, *args, **kwargs):
        role = self.get_object()
        if role.role_type == "system":
            return Response(
                {"error": "System roles cannot be deleted"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def clone(self, request, pk=None):
        role = self.get_object()
        new_name = request.data.get("name", f"{role.name}_copy")
        new_display_name = request.data.get("display_name", f"Copy of {role.display_name}")

        cloned_role = role.clone(new_name, new_display_name)
        serializer = self.get_serializer(cloned_role)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def assign_permissions(self, request, pk=None):
        role = self.get_object()
        permission_ids = request.data.get("permission_ids", [])

        if not permission_ids:
            return Response(
                {"error": "permission_ids is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        permissions = Permission.objects.filter(id__in=permission_ids)
        added = []

        with transaction.atomic():
            for permission in permissions:
                role_permission = role.add_permission(
                    permission,
                    conditions=request.data.get("conditions", {}),
                )
                added.append(role_permission)

        serializer = RolePermissionSerializer(added, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def remove_permissions(self, request, pk=None):
        role = self.get_object()
        permission_ids = request.data.get("permission_ids", [])

        if not permission_ids:
            return Response(
                {"error": "permission_ids is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        permissions = Permission.objects.filter(id__in=permission_ids)

        with transaction.atomic():
            for permission in permissions:
                role.remove_permission(permission)

        return Response({"message": "Permissions removed successfully"})

    @action(detail=True, methods=["get"])
    def users(self, request, pk=None):
        role = self.get_object()
        user_roles = UserRole.objects.filter(role=role, is_active=True)
        serializer = UserRoleSerializer(user_roles, many=True)
        return Response(serializer.data)


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset: ClassVar = UserRole.objects.all()
    serializer_class: ClassVar = UserRoleSerializer
    permission_classes: ClassVar = [IsAuthenticated, AidaPermission]
    filter_backends: ClassVar = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields: ClassVar = ["user", "role", "is_active"]
    ordering_fields: ClassVar = ["assigned_at", "expires_at"]
    ordering: ClassVar = ["-assigned_at"]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically set search_fields based on User model
        self.search_fields = get_user_search_fields()

    permission_required: ClassVar = {
        "list": "user_roles.view",
        "retrieve": "user_roles.view",
        "create": "user_roles.assign",
        "update": "user_roles.edit",
        "partial_update": "user_roles.edit",
        "destroy": "user_roles.revoke",
        "assign": "user_roles.assign",
        "bulk_assign": "user_roles.assign",
        "revoke": "user_roles.revoke",
    }

    def perform_create(self, serializer):
        serializer.save(assigned_by=self.request.user)

    @action(detail=False, methods=["post"])
    def assign(self, request):
        serializer = AssignRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(pk=serializer.validated_data["user_id"])
        role = Role.objects.get(pk=serializer.validated_data["role_id"])

        user_role, created = UserRole.objects.update_or_create(
            user=user,
            role=role,
            defaults={
                "is_active": True,
                "assigned_by": request.user,
                "expires_at": serializer.validated_data.get("expires_at"),
                "scope": serializer.validated_data.get("scope", {}),
                "tenant_id": getattr(request, "tenant_id", None),
            },
        )

        response_serializer = UserRoleSerializer(user_role)
        return Response(
            response_serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"])
    def bulk_assign(self, request):
        serializer = BulkAssignRoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        role = Role.objects.get(pk=serializer.validated_data["role_id"])
        users = User.objects.filter(pk__in=serializer.validated_data["user_ids"])

        created_roles = []
        with transaction.atomic():
            for user in users:
                user_role, created = UserRole.objects.update_or_create(
                    user=user,
                    role=role,
                    defaults={
                        "is_active": True,
                        "assigned_by": request.user,
                        "expires_at": serializer.validated_data.get("expires_at"),
                        "scope": serializer.validated_data.get("scope", {}),
                        "tenant_id": getattr(request, "tenant_id", None),
                    },
                )
                if created:
                    created_roles.append(user_role)

        response_serializer = UserRoleSerializer(created_roles, many=True)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        user_role = self.get_object()
        user_role.is_active = False
        user_role.save()
        return Response({"message": "Role revoked successfully"})

    @action(detail=False, methods=["get"])
    def my_roles(self, request):
        user_roles = UserRole.objects.filter(user=request.user, is_active=True)
        serializer = UserRoleSerializer(user_roles, many=True)
        return Response(serializer.data)


class UserPermissionViewSet(viewsets.ViewSet):
    permission_classes: ClassVar = [IsAuthenticated]

    @action(detail=False, methods=["get"])
    def check(self, request):
        permission = request.query_params.get("permission")
        if not permission:
            return Response(
                {"error": "Permission parameter is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))
        has_permission = checker.has_permission(permission)

        return Response({
            "permission": permission,
            "has_permission": has_permission,
        })

    @action(detail=False, methods=["post"])
    def check_multiple(self, request):
        permissions = request.data.get("permissions", [])
        if not permissions:
            return Response(
                {"error": "Permissions array is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        checker = PermissionChecker(request.user, getattr(request, "tenant_id", None))
        results = {}

        for permission in permissions:
            results[permission] = checker.has_permission(permission)

        return Response(results)

    @action(detail=False, methods=["get"])
    def user_permissions(self, request):
        user_id = request.query_params.get("user_id")

        if user_id and request.user.has_perm("permissions.view_user_permissions"):
            try:
                user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            user = request.user

        checker = PermissionChecker(user, getattr(request, "tenant_id", None))
        permissions = checker.get_user_permissions()
        roles = checker.get_user_roles()

        role_data = RoleSerializer(roles, many=True).data

        return Response({
            "user_id": str(user.id),
            "permissions": permissions,
            "roles": role_data,
        })
