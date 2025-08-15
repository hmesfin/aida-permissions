import { ref, computed } from 'vue'
import { usePermissionStore } from '../stores/permission'

export function usePermissions() {
  const store = usePermissionStore()
  const loading = ref(false)
  const error = ref(null)

  const hasPermission = (permission) => {
    if (typeof permission === 'string') {
      return store.hasPermission(permission)
    }
    
    if (Array.isArray(permission)) {
      return store.hasAnyPermission(permission)
    }
    
    return false
  }

  const hasAllPermissions = (permissions) => {
    return store.hasAllPermissions(permissions)
  }

  const hasAnyPermission = (permissions) => {
    return store.hasAnyPermission(permissions)
  }

  const hasRole = (roleName) => {
    return store.hasRole(roleName)
  }

  const hasAnyRole = (roleNames) => {
    return store.hasAnyRole(roleNames)
  }

  const checkPermission = async (permission) => {
    loading.value = true
    error.value = null
    
    try {
      const result = await store.checkPermission(permission)
      return result
    } catch (err) {
      error.value = err.message
      return false
    } finally {
      loading.value = false
    }
  }

  const checkMultiplePermissions = async (permissions) => {
    loading.value = true
    error.value = null
    
    try {
      const results = await store.checkMultiplePermissions(permissions)
      return results
    } catch (err) {
      error.value = err.message
      return {}
    } finally {
      loading.value = false
    }
  }

  const refreshPermissions = async () => {
    loading.value = true
    error.value = null
    
    try {
      await store.fetchUserPermissions()
    } catch (err) {
      error.value = err.message
    } finally {
      loading.value = false
    }
  }

  const can = (action, resource) => {
    const permission = `${resource}.${action}`
    return hasPermission(permission)
  }

  const cannot = (action, resource) => {
    return !can(action, resource)
  }

  const userPermissions = computed(() => store.permissions)
  const userRoles = computed(() => store.roles)
  const isLoaded = computed(() => store.isLoaded)

  return {
    hasPermission,
    hasAllPermissions,
    hasAnyPermission,
    hasRole,
    hasAnyRole,
    checkPermission,
    checkMultiplePermissions,
    refreshPermissions,
    can,
    cannot,
    userPermissions,
    userRoles,
    isLoaded,
    loading,
    error
  }
}