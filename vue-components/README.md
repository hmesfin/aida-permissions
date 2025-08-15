# Aida Permissions Vue.js Components

Vue.js 3 components and utilities for integrating with Aida Permissions Django backend.

## Installation

```bash
npm install aida-permissions-vue
```

## Setup

### 1. Install the plugin

```javascript
// main.js
```bash
npm install aida-permissions-vue
```

## Setup

### 1. Install the plugin

```javascript
// main.js
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import AidaPermissionsPlugin from 'aida-permissions-vue'
import App from './App.vue'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(AidaPermissionsPlugin, {
  apiBaseUrl: 'http://localhost:8000/api'
})

app.mount('#app')
```

### 2. Configure Axios

```javascript
// axios-config.js
import axios from 'axios'

axios.defaults.headers.common['Authorization'] = `Bearer ${localStorage.getItem('token')}`
axios.defaults.headers.common['X-Tenant-ID'] = localStorage.getItem('tenantId')
```

## Usage

### Composable

```vue
<script setup>
import { usePermissions } from 'aida-permissions-vue'

const { 
  hasPermission, 
  hasRole, 
  can, 
  cannot,
  refreshPermissions 
} = usePermissions()

const canEditEquipment = hasPermission('equipment.edit')
const isAdmin = hasRole('admin')
const canCreateRental = can('create', 'rental')

async function handleAction() {
  if (cannot('approve', 'rental')) {
    alert('You do not have permission to approve rentals')
    return
  }
  // Perform action
}
</script>
```

### Permission Guard Component

```vue
<template>
  <PermissionGuard permission="equipment.create">
    <button @click="createEquipment">Create Equipment</button>
  </PermissionGuard>

  <PermissionGuard 
    :permission="['rental.approve', 'rental.reject']"
    :show-fallback="true"
  >
    <div>Approval Actions</div>
    <template #fallback>
      <p>You need approval permissions to see this</p>
    </template>
  </PermissionGuard>

  <PermissionGuard 
    role="admin"
    :permission="['settings.view', 'settings.edit']"
    :require-all="true"
  >
    <AdminPanel />
  </PermissionGuard>
</template>
```

### Permission Directive

```vue
<template>
  <!-- Remove element if no permission -->
  <button v-permission="'equipment.delete'">
    Delete Equipment
  </button>

  <!-- Hide element if no permission -->
  <div v-permission.hide="'reports.view'">
    Reports Section
  </div>

  <!-- Disable element if no permission -->
  <button v-permission.disable="'equipment.edit'">
    Edit Equipment
  </button>

  <!-- Check multiple permissions (ANY) -->
  <button v-permission="['rental.approve', 'rental.reject']">
    Review Rental
  </button>

  <!-- Check multiple permissions (ALL) -->
  <button v-permission.all="['settings.view', 'settings.edit']">
    Manage Settings
  </button>

  <!-- Check role -->
  <div v-permission:role="'admin'">
    Admin Section
  </div>
</template>
```

### Role Manager Component

```vue
<template>
  <RoleManager />
</template>
```

### Store Usage

```javascript
import { usePermissionStore } from 'aida-permissions-vue'

const store = usePermissionStore()

// Check permissions
const hasPermission = store.hasPermission('equipment.create')
const hasAnyPermission = store.hasAnyPermission(['rental.view', 'rental.create'])
const hasAllPermissions = store.hasAllPermissions(['settings.view', 'settings.edit'])

// Check roles
const hasRole = store.hasRole('manager')
const hasAnyRole = store.hasAnyRole(['admin', 'manager'])

// Fetch latest permissions
await store.fetchUserPermissions()

// Check permission from API
const canApprove = await store.checkPermission('rental.approve')

// Check multiple permissions
const results = await store.checkMultiplePermissions([
  'equipment.create',
  'equipment.edit',
  'equipment.delete'
])

// Clear cached permissions (e.g., on logout)
store.clearPermissions()
```

## API Reference

### usePermissions()

Returns:

- `hasPermission(permission)`: Check single permission
- `hasAllPermissions(permissions)`: Check if user has all permissions
- `hasAnyPermission(permissions)`: Check if user has any permission
- `hasRole(roleName)`: Check if user has role
- `hasAnyRole(roleNames)`: Check if user has any role
- `can(action, resource)`: Check permission in format `resource.action`
- `cannot(action, resource)`: Inverse of `can()`
- `checkPermission(permission)`: Check permission via API
- `checkMultiplePermissions(permissions)`: Check multiple permissions via API
- `refreshPermissions()`: Refresh permissions from server
- `userPermissions`: Computed array of user permissions
- `userRoles`: Computed array of user roles
- `isLoaded`: Computed boolean if permissions are loaded
- `loading`: Ref boolean for loading state
- `error`: Ref for error messages

### PermissionGuard Props

- `permission`: String or Array - Permission(s) to check
- `role`: String or Array - Role(s) to check
- `requireAll`: Boolean - Require all permissions/roles (default: false)
- `showFallback`: Boolean - Show fallback content (default: false)
- `fallbackMessage`: String - Fallback message text

### v-permission Directive

Modifiers:

- `.hide`: Hide element instead of removing
- `.disable`: Disable element instead of removing
- `.all`: Require all permissions (for arrays)

Arguments:

- `:role`: Check role instead of permission

## Examples

### Protected Route

```javascript
// router.js
import { usePermissionStore } from 'aida-permissions-vue'

router.beforeEach(async (to, from, next) => {
  const store = usePermissionStore()
  
  if (!store.isLoaded) {
    await store.fetchUserPermissions()
  }
  
  if (to.meta.permission) {
    if (store.hasPermission(to.meta.permission)) {
      next()
    } else {
      next('/unauthorized')
    }
  } else {
    next()
  }
})
```

### Dynamic Menu

```vue
<template>
  <nav>
    <router-link 
      v-permission="'equipment.view'"
      to="/equipment"
    >
      Equipment
    </router-link>
    
    <router-link 
      v-permission="'rental.view'"
      to="/rentals"
    >
      Rentals
    </router-link>
    
    <router-link 
      v-permission:role="'admin'"
      to="/admin"
    >
      Admin
    </router-link>
  </nav>
</template>
```

### Conditional Actions

```vue
<template>
  <div class="equipment-card">
    <h3>{{ equipment.name }}</h3>
    
    <div class="actions">
      <button 
        v-permission.disable="'equipment.edit'"
        @click="editEquipment"
      >
        Edit
      </button>
      
      <button 
        v-permission="'equipment.delete'"
        @click="deleteEquipment"
        class="danger"
      >
        Delete
      </button>
    </div>
  </div>
</template>
```

## TypeScript Support

```typescript
import { usePermissions } from 'aida-permissions-vue'

interface Permission {
  hasPermission: (permission: string | string[]) => boolean
  hasRole: (role: string) => boolean
  // ... other methods
}

const permissions: Permission = usePermissions()
```
