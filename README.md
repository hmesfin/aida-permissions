# AIDA Permissions

A flexible and powerful Django roles and permissions extension optimized for Django REST Framework and Vue.js frontends.

[![Python](https://img.shields.io/pypi/pyversions/aida-permissions.svg)](https://pypi.org/project/aida-permissions/)
[![Django](https://img.shields.io/badge/Django-3.2%20to%205.1-green.svg)](https://www.djangoproject.com/)
[![License](https://img.shields.io/pypi/l/aida-permissions.svg)](https://github.com/hmesfin/aida-permissions/blob/main/LICENSE)

## Features

- 🔐 **Role-Based Access Control (RBAC)** with inheritance support
- 🏢 **Multi-tenancy** ready with tenant isolation
- ⚡ **Optimized for REST APIs** with Django REST Framework integration
- 🎯 **Vue.js components** for frontend integration
- 🔄 **Dynamic permissions** that can be created and assigned at runtime
- ⏰ **Time-based permissions** with expiration support
- 🎨 **Admin interface** for easy management
- 🚀 **High performance** with intelligent caching
- 📝 **Comprehensive audit logging**

## Requirements

- Python 3.8+
- Django 3.2, 4.0, 4.1, 4.2, 5.0, or 5.1
- Django REST Framework 3.12+

## Installation

Install using pip:

```bash
pip install aida-permissions
```

Add to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'aida_permissions',
    'rest_framework',
    # ...
]
```

Add the middleware (optional but recommended):

```python
MIDDLEWARE = [
    # ...
    'aida_permissions.middleware.PermissionMiddleware',
    # ...
]
```

Run migrations:

```bash
python manage.py migrate aida_permissions
```

Initialize default permissions:

```bash
python manage.py init_permissions
```

## Quick Start

### 1. Define Roles and Permissions

```python
from aida_permissions.models import Role, Permission, PermissionCategory

# Create a permission category
category = PermissionCategory.objects.create(
    name="products",
    display_name="Product Management"
)

# Create permissions
view_permission = Permission.objects.create(
    codename="products.view",
    name="View Products",
    category=category
)

edit_permission = Permission.objects.create(
    codename="products.edit",
    name="Edit Products",
    category=category
)

# Create a role
manager_role = Role.objects.create(
    name="product_manager",
    display_name="Product Manager"
)

# Assign permissions to role
manager_role.add_permission(view_permission)
manager_role.add_permission(edit_permission)
```

### 2. Assign Roles to Users

```python
from aida_permissions.models import UserRole
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.get(username="john")

# Assign role to user
UserRole.objects.create(
    user=user,
    role=manager_role
)
```

### 3. Check Permissions in Views

```python
from rest_framework import viewsets
from aida_permissions.permissions import AidaPermission

class ProductViewSet(viewsets.ModelViewSet):
    permission_classes = [AidaPermission]
    
    # Define required permissions for each action
    permission_required = {
        'list': 'products.view',
        'retrieve': 'products.view',
        'create': 'products.create',
        'update': 'products.edit',
        'destroy': 'products.delete',
    }
```

### 4. Check Permissions in Code

```python
from aida_permissions.utils import has_permission

if has_permission(user, 'products.edit'):
    # User can edit products
    product.save()
```

### 5. Use in Templates (Vue.js)

```vue
<template>
  <div>
    <button v-if="can('products.edit')" @click="editProduct">
      Edit Product
    </button>
  </div>
</template>

<script>
import { usePermissions } from '@/composables/usePermissions'

export default {
  setup() {
    const { can } = usePermissions()
    return { can }
  }
}
</script>
```

## Advanced Features

### Role Inheritance

```python
# Create parent role
base_role = Role.objects.create(
    name="employee",
    display_name="Employee"
)

# Create child role that inherits permissions
manager_role = Role.objects.create(
    name="manager",
    display_name="Manager",
    parent_role=base_role  # Inherits all employee permissions
)
```

### Time-based Permissions

```python
from datetime import timedelta
from django.utils import timezone

# Assign role with expiration
UserRole.objects.create(
    user=user,
    role=temp_role,
    expires_at=timezone.now() + timedelta(days=30)
)
```

### Multi-tenancy Support

```python
# Create tenant-specific role
role = Role.objects.create(
    name="tenant_admin",
    display_name="Tenant Admin",
    tenant_id=tenant.id
)

# Check permission with tenant context
from aida_permissions.utils import PermissionChecker

checker = PermissionChecker(user, tenant_id=tenant.id)
if checker.has_permission('products.edit'):
    # User can edit products in this tenant
    pass
```

### Custom Permission Conditions

```python
# Add permission with conditions
role.add_permission(
    permission,
    conditions={
        'department': 'sales',
        'region': 'north'
    }
)
```

## API Endpoints

The package provides ready-to-use API endpoints:

- `GET /api/permissions/` - List permissions
- `GET /api/roles/` - List roles  
- `POST /api/roles/{id}/assign_permissions/` - Assign permissions to role
- `GET /api/user-permissions/check/` - Check current user permissions
- `POST /api/user-roles/assign/` - Assign role to user

## Management Commands

```bash
# Initialize default permissions
python manage.py init_permissions

# Audit permissions usage
python manage.py audit_permissions

# Clean expired permissions
python manage.py cleanup_expired_permissions
```

## Configuration

Add to your Django settings:

```python
# Optional: Custom user model
AUTH_USER_MODEL = 'myapp.User'

# Optional: Caching backend for better performance
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}

# Optional: Default role for new users
AIDA_DEFAULT_ROLE = 'member'

# Optional: Permission check failure behavior
AIDA_PERMISSION_DENIED_RAISES = True
```

## Testing

Run the test suite:

```bash
pytest
```

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [https://github.com/hmesfin/aida-permissions](https://github.com/hmesfin/aida-permissions)
- Issues: [https://github.com/hmesfin/aida-permissions/issues](https://github.com/hmesfin/aida-permissions/issues)

## Author

- GitHub: [@hmesfin](https://github.com/hmesfin)

## Acknowledgments

- Built with Django and Django REST Framework
- Inspired by django-guardian and django-role-permissions