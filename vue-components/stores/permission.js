import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

export const usePermissionStore = defineStore('permission', () => {
  const permissions = ref([])
  const roles = ref([])
  const isLoaded = ref(false)
  const loading = ref(false)
  const error = ref(null)

  const apiBaseUrl = import.meta.env.VITE_API_URL || '/api'

  const hasPermission = computed(() => (permission) => {
    if (!isLoaded.value) return false
    
    if (permissions.value.includes(permission)) {
      return true
    }
    
    const parts = permission.split('.')
    if (parts.length === 2) {
      const [resource, action] = parts
      return permissions.value.includes(`${resource}.*`) ||
             permissions.value.includes(`*.${action}`) ||
             permissions.value.includes('*.*')
    }
    
    return false
  })

  const hasAllPermissions = computed(() => (permissionList) => {
    if (!isLoaded.value) return false
    return permissionList.every(perm => hasPermission.value(perm))
  })

  const hasAnyPermission = computed(() => (permissionList) => {
    if (!isLoaded.value) return false
    return permissionList.some(perm => hasPermission.value(perm))
  })

  const hasRole = computed(() => (roleName) => {
    if (!isLoaded.value) return false
    return roles.value.some(role => role.name === roleName)
  })

  const hasAnyRole = computed(() => (roleNames) => {
    if (!isLoaded.value) return false
    return roleNames.some(roleName => hasRole.value(roleName))
  })

  const fetchUserPermissions = async () => {
    loading.value = true
    error.value = null
    
    try {
      const response = await axios.get(`${apiBaseUrl}/permissions/user-permissions/`)
      permissions.value = response.data.permissions || []
      roles.value = response.data.roles || []
      isLoaded.value = true
      
      localStorage.setItem('userPermissions', JSON.stringify(permissions.value))
      localStorage.setItem('userRoles', JSON.stringify(roles.value))
      
      return response.data
    } catch (err) {
      error.value = err.message
      console.error('Failed to fetch user permissions:', err)
      
      const cachedPermissions = localStorage.getItem('userPermissions')
      const cachedRoles = localStorage.getItem('userRoles')
      
      if (cachedPermissions) {
        permissions.value = JSON.parse(cachedPermissions)
      }
      if (cachedRoles) {
        roles.value = JSON.parse(cachedRoles)
      }
      
      isLoaded.value = !!(cachedPermissions || cachedRoles)
      throw err
    } finally {
      loading.value = false
    }
  }

  const checkPermission = async (permission) => {
    try {
      const response = await axios.get(`${apiBaseUrl}/permissions/check/`, {
        params: { permission }
      })
      return response.data.has_permission
    } catch (err) {
      console.error('Failed to check permission:', err)
      return hasPermission.value(permission)
    }
  }

  const checkMultiplePermissions = async (permissionList) => {
    try {
      const response = await axios.post(`${apiBaseUrl}/permissions/check-multiple/`, {
        permissions: permissionList
      })
      return response.data
    } catch (err) {
      console.error('Failed to check multiple permissions:', err)
      
      const results = {}
      permissionList.forEach(perm => {
        results[perm] = hasPermission.value(perm)
      })
      return results
    }
  }

  const clearPermissions = () => {
    permissions.value = []
    roles.value = []
    isLoaded.value = false
    localStorage.removeItem('userPermissions')
    localStorage.removeItem('userRoles')
  }

  const init = async () => {
    if (!isLoaded.value) {
      await fetchUserPermissions()
    }
  }

  return {
    permissions,
    roles,
    isLoaded,
    loading,
    error,
    hasPermission,
    hasAllPermissions,
    hasAnyPermission,
    hasRole,
    hasAnyRole,
    fetchUserPermissions,
    checkPermission,
    checkMultiplePermissions,
    clearPermissions,
    init
  }
})