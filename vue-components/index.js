import { usePermissions } from './composables/usePermissions'
import { usePermissionStore } from './stores/permission'
import PermissionGuard from './components/PermissionGuard.vue'
import RoleManager from './components/RoleManager.vue'
import vPermission from './directives/v-permission'

const AidaPermissionsPlugin = {
  install(app, options = {}) {
    const { apiBaseUrl } = options
    
    if (apiBaseUrl) {
      window.AIDA_PERMISSIONS_API_URL = apiBaseUrl
    }
    
    app.component('PermissionGuard', PermissionGuard)
    app.component('RoleManager', RoleManager)
    
    app.directive('permission', vPermission)
    
    const store = usePermissionStore()
    store.init()
    
    app.config.globalProperties.$permissions = {
      hasPermission: store.hasPermission,
      hasRole: store.hasRole,
      hasAnyPermission: store.hasAnyPermission,
      hasAllPermissions: store.hasAllPermissions
    }
  }
}

export {
  AidaPermissionsPlugin,
  usePermissions,
  usePermissionStore,
  PermissionGuard,
  RoleManager,
  vPermission
}

export default AidaPermissionsPlugin