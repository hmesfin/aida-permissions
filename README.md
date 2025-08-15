# Aida Permissions

A flexible, secure Django roles and permissions extension optimized for Django REST Framework and Vue.js frontends.

## Features

- **Dynamic Role Management**: Create and manage custom roles through admin interface or API
- **Granular Permissions**: Fine-grained permission control at model and object level
- **DRF Integration**: Built-in serializers, viewsets, and permission classes
- **Vue.js Components**: Ready-to-use frontend components for permission management
- **Caching**: Optimized performance with intelligent caching
- **Multi-tenancy Support**: Optional tenant-based permission isolation
- **Audit Trail**: Track permission changes and access attempts

## Installation

```bash
pip install aida-permissions
```

## Quick Start

1. Add to INSTALLED_APPS:

```python
INSTALLED_APPS = [
    ...
    'aida_permissions',
    'rest_framework',
]
```

2. Add middleware:

```python
MIDDLEWARE = [
    ...
    'aida_permissions.middleware.PermissionMiddleware',
]
```

3. Run migrations:

```bash
python manage.py migrate aida_permissions
```

4. Initialize default permissions:

```bash
python manage.py init_permissions
```

## Usage

### Define Permissions

```python
from aida_permissions.decorators import require_permission

@require_permission('equipment.view')
def view_equipment(request):
    pass

@require_permission(['equipment.create', 'equipment.edit'])
def manage_equipment(request):
    pass
```

### DRF Integration

```python
from aida_permissions.permissions import AidaPermission

class EquipmentViewSet(viewsets.ModelViewSet):
    permission_classes = [AidaPermission]
    permission_required = {
        'list': 'equipment.view',
        'create': 'equipment.create',
        'update': 'equipment.edit',
        'destroy': 'equipment.delete',
    }
```

### Vue.js Integration

```vue
<template>
  <div v-if="hasPermission('equipment.create')">
    <button @click="createEquipment">Create Equipment</button>
  </div>
</template>

<script>
import { usePermissions } from '@/aida-permissions'

export default {
  setup() {
    const { hasPermission } = usePermissions()
    return { hasPermission }
  }
}
</script>
```

## License

MIT