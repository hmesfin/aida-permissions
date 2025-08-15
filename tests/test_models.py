import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from aida_permissions.models import (
    Permission, PermissionCategory, Role, RolePermission, UserRole
)

User = get_user_model()


@pytest.mark.django_db
class TestPermissionCategory:
    def test_create_category(self):
        category = PermissionCategory.objects.create(
            name='test_category',
            display_name='Test Category',
            description='Test description',
            order=1
        )
        assert category.name == 'test_category'
        assert category.display_name == 'Test Category'
        assert category.is_active is True
        assert str(category) == 'Test Category'

    def test_category_ordering(self):
        cat1 = PermissionCategory.objects.create(name='cat1', display_name='Cat 1', order=2)
        cat2 = PermissionCategory.objects.create(name='cat2', display_name='Cat 2', order=1)
        cats = list(PermissionCategory.objects.all())
        assert cats[0] == cat2
        assert cats[1] == cat1


@pytest.mark.django_db
class TestPermission:
    def setup_method(self):
        self.category = PermissionCategory.objects.create(
            name='test_category',
            display_name='Test Category'
        )

    def test_create_permission(self):
        permission = Permission.objects.create(
            codename='test.view',
            name='View Test',
            category=self.category,
            permission_type='view',
            resource='test'
        )
        assert permission.codename == 'test.view'
        assert permission.name == 'View Test'
        assert permission.is_active is True
        assert permission.is_system is False

    def test_auto_generate_codename(self):
        permission = Permission.objects.create(
            name='Create Test',
            category=self.category,
            permission_type='create',
            resource='test'
        )
        permission.save()
        assert permission.codename == 'test.create'

    def test_system_permission_cannot_be_deleted(self):
        permission = Permission.objects.create(
            codename='system.critical',
            name='Critical System Permission',
            category=self.category,
            is_system=True
        )
        with pytest.raises(ValueError, match="System permissions cannot be deleted"):
            permission.delete()

    def test_get_by_codename(self):
        permission = Permission.objects.create(
            codename='test.unique',
            name='Unique Test',
            category=self.category
        )
        found = Permission.get_by_codename('test.unique')
        assert found == permission
        
        not_found = Permission.get_by_codename('nonexistent')
        assert not_found is None


@pytest.mark.django_db
class TestRole:
    def setup_method(self):
        self.category = PermissionCategory.objects.create(
            name='test_category',
            display_name='Test Category'
        )
        self.permission1 = Permission.objects.create(
            codename='test.view',
            name='View Test',
            category=self.category
        )
        self.permission2 = Permission.objects.create(
            codename='test.create',
            name='Create Test',
            category=self.category
        )

    def test_create_role(self):
        role = Role.objects.create(
            name='test_role',
            display_name='Test Role',
            description='Test role description',
            priority=50
        )
        assert role.name == 'test_role'
        assert role.display_name == 'Test Role'
        assert role.role_type == 'custom'
        assert role.is_active is True

    def test_default_role_uniqueness(self):
        role1 = Role.objects.create(name='role1', display_name='Role 1', is_default=True)
        role2 = Role.objects.create(name='role2', display_name='Role 2', is_default=True)
        
        role1.refresh_from_db()
        assert role1.is_default is False
        assert role2.is_default is True

    def test_system_role_cannot_be_deleted(self):
        role = Role.objects.create(
            name='system_role',
            display_name='System Role',
            role_type='system'
        )
        with pytest.raises(ValueError, match="System roles cannot be deleted"):
            role.delete()

    def test_add_permission_to_role(self):
        role = Role.objects.create(name='test_role', display_name='Test Role')
        role_permission = role.add_permission(self.permission1)
        
        assert role_permission.role == role
        assert role_permission.permission == self.permission1
        assert role.permissions.count() == 1

    def test_remove_permission_from_role(self):
        role = Role.objects.create(name='test_role', display_name='Test Role')
        role.add_permission(self.permission1)
        role.add_permission(self.permission2)
        assert role.permissions.count() == 2
        
        role.remove_permission(self.permission1)
        assert role.permissions.count() == 1
        assert self.permission2 in role.permissions.all()

    def test_role_inheritance(self):
        parent_role = Role.objects.create(name='parent', display_name='Parent Role')
        parent_role.add_permission(self.permission1)
        
        child_role = Role.objects.create(
            name='child',
            display_name='Child Role',
            parent_role=parent_role
        )
        child_role.add_permission(self.permission2)
        
        all_permissions = child_role.get_all_permissions(include_inherited=True)
        assert self.permission1 in all_permissions
        assert self.permission2 in all_permissions

    def test_has_permission(self):
        role = Role.objects.create(name='test_role', display_name='Test Role')
        role.add_permission(self.permission1)
        
        assert role.has_permission('test.view') is True
        assert role.has_permission('test.create') is False

    def test_clone_role(self):
        original = Role.objects.create(
            name='original',
            display_name='Original Role',
            description='Original description'
        )
        original.add_permission(self.permission1)
        original.add_permission(self.permission2)
        
        cloned = original.clone('cloned', 'Cloned Role')
        
        assert cloned.name == 'cloned'
        assert cloned.display_name == 'Cloned Role'
        assert cloned.permissions.count() == 2
        assert self.permission1 in cloned.permissions.all()
        assert self.permission2 in cloned.permissions.all()


@pytest.mark.django_db
class TestUserRole:
    def setup_method(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.role = Role.objects.create(
            name='test_role',
            display_name='Test Role'
        )

    def test_assign_role_to_user(self):
        user_role = UserRole.objects.create(
            user=self.user,
            role=self.role
        )
        assert user_role.user == self.user
        assert user_role.role == self.role
        assert user_role.is_active is True
        assert user_role.is_valid() is True

    def test_role_expiration(self):
        expired_date = timezone.now() - timedelta(days=1)
        user_role = UserRole.objects.create(
            user=self.user,
            role=self.role,
            expires_at=expired_date
        )
        assert user_role.is_valid() is False

    def test_max_users_limit(self):
        limited_role = Role.objects.create(
            name='limited_role',
            display_name='Limited Role',
            max_users=2
        )
        
        user2 = User.objects.create_user(username='user2', password='pass')
        user3 = User.objects.create_user(username='user3', password='pass')
        
        UserRole.objects.create(user=self.user, role=limited_role)
        UserRole.objects.create(user=user2, role=limited_role)
        
        with pytest.raises(ValueError, match="has reached maximum user limit"):
            UserRole.objects.create(user=user3, role=limited_role)

    def test_unique_user_role_per_tenant(self):
        UserRole.objects.create(
            user=self.user,
            role=self.role,
            tenant_id='tenant1'
        )
        
        with pytest.raises(Exception):
            UserRole.objects.create(
                user=self.user,
                role=self.role,
                tenant_id='tenant1'
            )


@pytest.mark.django_db
class TestRolePermission:
    def setup_method(self):
        self.category = PermissionCategory.objects.create(
            name='test_category',
            display_name='Test Category'
        )
        self.permission = Permission.objects.create(
            codename='test.view',
            name='View Test',
            category=self.category
        )
        self.role = Role.objects.create(
            name='test_role',
            display_name='Test Role'
        )

    def test_role_permission_validity(self):
        role_perm = RolePermission.objects.create(
            role=self.role,
            permission=self.permission
        )
        assert role_perm.is_valid() is True
        
        role_perm.is_active = False
        assert role_perm.is_valid() is False

    def test_role_permission_expiration(self):
        future_date = timezone.now() + timedelta(days=30)
        role_perm = RolePermission.objects.create(
            role=self.role,
            permission=self.permission,
            expires_at=future_date
        )
        assert role_perm.is_valid() is True
        
        past_date = timezone.now() - timedelta(days=1)
        role_perm.expires_at = past_date
        assert role_perm.is_valid() is False

    def test_role_permission_conditions(self):
        conditions = {
            'ip_range': '192.168.1.0/24',
            'time_range': '09:00-17:00'
        }
        role_perm = RolePermission.objects.create(
            role=self.role,
            permission=self.permission,
            conditions=conditions
        )
        assert role_perm.conditions == conditions