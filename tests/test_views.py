import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from aida_permissions.models import Permission, PermissionCategory, Role, UserRole

User = get_user_model()


@pytest.mark.django_db
class TestPermissionViewSet:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.admin = User.objects.create_user(
            username="admin",
            password="adminpass123",
            is_superuser=True,
        )
        self.category = PermissionCategory.objects.create(
            name="test",
            display_name="Test Category",
        )
        self.permission = Permission.objects.create(
            codename="test.view",
            name="View Test",
            category=self.category,
            resource="test",
            permission_type="view",
        )

    def test_list_permissions_authenticated(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/permissions/")
        assert response.status_code == 200
        assert len(response.data) > 0

    def test_list_permissions_unauthenticated(self):
        response = self.client.get("/api/permissions/")
        assert response.status_code == 401

    def test_create_permission(self):
        self.client.force_authenticate(user=self.admin)
        data = {
            "codename": "test.create",
            "name": "Create Test",
            "category": self.category.id,
            "resource": "test",
            "permission_type": "create",
        }
        response = self.client.post("/api/permissions/", data)
        assert response.status_code == 201
        assert response.data["codename"] == "test.create"

    def test_update_permission(self):
        self.client.force_authenticate(user=self.admin)
        data = {"name": "Updated Test Permission"}
        response = self.client.patch(f"/api/permissions/{self.permission.id}/", data)
        assert response.status_code == 200
        assert response.data["name"] == "Updated Test Permission"

    def test_delete_system_permission(self):
        system_perm = Permission.objects.create(
            codename="system.critical",
            name="Critical Permission",
            category=self.category,
            is_system=True,
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(f"/api/permissions/{system_perm.id}/")
        assert response.status_code == 400

    def test_my_permissions_endpoint(self):
        role = Role.objects.create(name="test_role", display_name="Test Role")
        role.add_permission(self.permission)
        UserRole.objects.create(user=self.user, role=role)

        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/permissions/my-permissions/")
        assert response.status_code == 200
        assert "test.view" in response.data["permissions"]


@pytest.mark.django_db
class TestRoleViewSet:
    def setup_method(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="admin",
            password="adminpass123",
            is_superuser=True,
        )
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.category = PermissionCategory.objects.create(
            name="test",
            display_name="Test Category",
        )
        self.permission = Permission.objects.create(
            codename="test.view",
            name="View Test",
            category=self.category,
        )
        self.role = Role.objects.create(
            name="test_role",
            display_name="Test Role",
        )

    def test_list_roles(self):
        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/roles/")
        assert response.status_code == 200

    def test_create_role(self):
        self.client.force_authenticate(user=self.admin)
        data = {
            "name": "new_role",
            "display_name": "New Role",
            "description": "A new role",
            "priority": 50,
        }
        response = self.client.post("/api/roles/", data)
        assert response.status_code == 201
        assert response.data["name"] == "new_role"

    def test_clone_role(self):
        self.role.add_permission(self.permission)
        self.client.force_authenticate(user=self.admin)
        data = {
            "name": "cloned_role",
            "display_name": "Cloned Role",
        }
        response = self.client.post(f"/api/roles/{self.role.id}/clone/", data)
        assert response.status_code == 201
        assert response.data["name"] == "cloned_role"
        assert response.data["permission_count"] == 1

    def test_assign_permissions_to_role(self):
        self.client.force_authenticate(user=self.admin)
        data = {"permission_ids": [str(self.permission.id)]}
        response = self.client.post(f"/api/roles/{self.role.id}/assign-permissions/", data)
        assert response.status_code == 201

        self.role.refresh_from_db()
        assert self.role.permissions.count() == 1

    def test_remove_permissions_from_role(self):
        self.role.add_permission(self.permission)
        self.client.force_authenticate(user=self.admin)
        data = {"permission_ids": [str(self.permission.id)]}
        response = self.client.post(f"/api/roles/{self.role.id}/remove-permissions/", data)
        assert response.status_code == 200

        self.role.refresh_from_db()
        assert self.role.permissions.count() == 0

    def test_delete_system_role(self):
        system_role = Role.objects.create(
            name="system_role",
            display_name="System Role",
            role_type="system",
        )
        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(f"/api/roles/{system_role.id}/")
        assert response.status_code == 400


@pytest.mark.django_db
class TestUserRoleViewSet:
    def setup_method(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="admin",
            password="adminpass123",
            is_superuser=True,
        )
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.role = Role.objects.create(
            name="test_role",
            display_name="Test Role",
        )

    def test_assign_role(self):
        self.client.force_authenticate(user=self.admin)
        data = {
            "user_id": str(self.user.id),
            "role_id": str(self.role.id),
        }
        response = self.client.post("/api/user-roles/assign/", data)
        assert response.status_code == 201
        assert UserRole.objects.filter(user=self.user, role=self.role).exists()

    def test_bulk_assign_roles(self):
        user2 = User.objects.create_user(username="user2", password="pass")
        self.client.force_authenticate(user=self.admin)
        data = {
            "user_ids": [str(self.user.id), str(user2.id)],
            "role_id": str(self.role.id),
        }
        response = self.client.post("/api/user-roles/bulk-assign/", data)
        assert response.status_code == 201
        assert UserRole.objects.filter(role=self.role).count() == 2

    def test_revoke_role(self):
        user_role = UserRole.objects.create(user=self.user, role=self.role)
        self.client.force_authenticate(user=self.admin)
        response = self.client.post(f"/api/user-roles/{user_role.id}/revoke/")
        assert response.status_code == 200

        user_role.refresh_from_db()
        assert user_role.is_active is False

    def test_my_roles(self):
        UserRole.objects.create(user=self.user, role=self.role)
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/user-roles/my-roles/")
        assert response.status_code == 200
        assert len(response.data) == 1
        assert response.data[0]["role"]["name"] == "test_role"


@pytest.mark.django_db
class TestUserPermissionViewSet:
    def setup_method(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.category = PermissionCategory.objects.create(
            name="test",
            display_name="Test Category",
        )
        self.permission = Permission.objects.create(
            codename="test.view",
            name="View Test",
            category=self.category,
        )
        self.role = Role.objects.create(
            name="test_role",
            display_name="Test Role",
        )
        self.role.add_permission(self.permission)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_check_permission(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/user-permissions/check/", {"permission": "test.view"})
        assert response.status_code == 200
        assert response.data["has_permission"] is True

    def test_check_multiple_permissions(self):
        self.client.force_authenticate(user=self.user)
        data = {"permissions": ["test.view", "test.create"]}
        response = self.client.post("/api/user-permissions/check-multiple/", data)
        assert response.status_code == 200
        assert response.data["test.view"] is True
        assert response.data["test.create"] is False

    def test_user_permissions(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/user-permissions/user-permissions/")
        assert response.status_code == 200
        assert "test.view" in response.data["permissions"]
        assert len(response.data["roles"]) == 1
