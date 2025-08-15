import pytest
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from aida_permissions.models import Permission, PermissionCategory, Role, UserRole
from aida_permissions.utils import PermissionChecker, has_permission, get_user_permissions
from aida_permissions.permissions import AidaPermission, HasRolePermission

User = get_user_model()


@pytest.mark.django_db
class TestPermissionChecker:
    def setup_method(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.category = PermissionCategory.objects.create(
            name='test',
            display_name='Test'
        )
        self.permission1 = Permission.objects.create(
            codename='test.view',
            name='View Test',
            category=self.category,
            resource='test',
            permission_type='view'
        )
        self.permission2 = Permission.objects.create(
            codename='test.create',
            name='Create Test',
            category=self.category,
            resource='test',
            permission_type='create'
        )
        self.role = Role.objects.create(
            name='test_role',
            display_name='Test Role'
        )
        self.role.add_permission(self.permission1)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_has_permission(self):
        checker = PermissionChecker(self.user)
        assert checker.has_permission('test.view') is True
        assert checker.has_permission('test.create') is False
        assert checker.has_permission('nonexistent.permission') is False

    def test_has_permission_superuser(self):
        self.user.is_superuser = True
        self.user.save()
        checker = PermissionChecker(self.user)
        assert checker.has_permission('any.permission') is True

    def test_wildcard_permissions(self):
        wildcard_perm = Permission.objects.create(
            codename='test.*',
            name='All Test Permissions',
            category=self.category
        )
        self.role.add_permission(wildcard_perm)
        
        checker = PermissionChecker(self.user)
        checker.clear_cache()
        assert checker.has_permission('test.delete') is True
        assert checker.has_permission('other.view') is False

    def test_has_any_permission(self):
        checker = PermissionChecker(self.user)
        assert checker.has_any_permission(['test.view', 'test.create']) is True
        assert checker.has_any_permission(['test.create', 'test.delete']) is False

    def test_has_all_permissions(self):
        checker = PermissionChecker(self.user)
        assert checker.has_all_permissions(['test.view']) is True
        assert checker.has_all_permissions(['test.view', 'test.create']) is False

    def test_has_role(self):
        checker = PermissionChecker(self.user)
        assert checker.has_role('test_role') is True
        assert checker.has_role('nonexistent_role') is False

    def test_get_user_permissions(self):
        checker = PermissionChecker(self.user)
        permissions = checker.get_user_permissions()
        assert 'test.view' in permissions
        assert 'test.create' not in permissions

    def test_tenant_filtering(self):
        tenant_role = Role.objects.create(
            name='tenant_role',
            display_name='Tenant Role',
            tenant_id='tenant1'
        )
        tenant_perm = Permission.objects.create(
            codename='tenant.special',
            name='Tenant Special',
            category=self.category,
            tenant_id='tenant1'
        )
        tenant_role.add_permission(tenant_perm)
        UserRole.objects.create(
            user=self.user,
            role=tenant_role,
            tenant_id='tenant1'
        )
        
        checker = PermissionChecker(self.user, tenant_id='tenant1')
        assert checker.has_permission('tenant.special') is True
        
        checker2 = PermissionChecker(self.user, tenant_id='tenant2')
        assert checker2.has_permission('tenant.special') is False

    def test_cache_clearing(self):
        checker = PermissionChecker(self.user)
        assert checker.has_permission('test.view') is True
        
        self.role.remove_permission(self.permission1)
        assert checker.has_permission('test.view') is True
        
        checker.clear_cache()
        assert checker.has_permission('test.view') is False


@pytest.mark.django_db
class TestAidaPermission:
    def setup_method(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.category = PermissionCategory.objects.create(
            name='test',
            display_name='Test'
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
        self.role.add_permission(self.permission)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_has_permission_authenticated(self):
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.action = 'list'
        view.permission_required = {'list': 'test.view'}
        
        permission = AidaPermission()
        assert permission.has_permission(request, view) is True

    def test_has_permission_unauthenticated(self):
        request = self.factory.get('/')
        request.user = None
        
        view = Mock()
        permission = AidaPermission()
        assert permission.has_permission(request, view) is False

    def test_has_permission_superuser(self):
        self.user.is_superuser = True
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.action = 'destroy'
        view.permission_required = {'destroy': 'admin.delete_everything'}
        
        permission = AidaPermission()
        assert permission.has_permission(request, view) is True

    def test_has_permission_missing(self):
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.action = 'create'
        view.permission_required = {'create': 'test.create'}
        
        permission = AidaPermission()
        with patch.object(PermissionChecker, '__init__', return_value=None):
            with patch.object(PermissionChecker, 'has_permission', return_value=False):
                assert permission.has_permission(request, view) is False

    def test_has_permission_multiple(self):
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.action = 'custom'
        view.permission_required = {'custom': ['test.view', 'test.nonexistent']}
        
        permission = AidaPermission()
        with patch.object(PermissionChecker, '__init__', return_value=None):
            with patch.object(PermissionChecker, 'has_permission', side_effect=[True, False]):
                assert permission.has_permission(request, view) is True


@pytest.mark.django_db
class TestHasRolePermission:
    def setup_method(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.role = Role.objects.create(
            name='manager',
            display_name='Manager'
        )
        UserRole.objects.create(user=self.user, role=self.role)

    def test_has_role_permission(self):
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.required_roles = ['manager']
        
        permission = HasRolePermission()
        with patch.object(PermissionChecker, '__init__', return_value=None):
            with patch.object(PermissionChecker, 'get_role_names', return_value=['manager']):
                assert permission.has_permission(request, view) is True

    def test_has_role_permission_missing(self):
        request = self.factory.get('/')
        request.user = self.user
        
        view = Mock()
        view.required_roles = ['admin']
        
        permission = HasRolePermission()
        with patch.object(PermissionChecker, '__init__', return_value=None):
            with patch.object(PermissionChecker, 'get_role_names', return_value=['manager']):
                assert permission.has_permission(request, view) is False


@pytest.mark.django_db
class TestUtilityFunctions:
    def setup_method(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.category = PermissionCategory.objects.create(
            name='test',
            display_name='Test'
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
        self.role.add_permission(self.permission)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_has_permission_utility(self):
        assert has_permission(self.user, 'test.view') is True
        assert has_permission(self.user, 'test.create') is False

    def test_get_user_permissions_utility(self):
        permissions = get_user_permissions(self.user)
        assert 'test.view' in permissions
        assert len(permissions) == 1