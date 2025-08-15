import { usePermissionStore } from '../stores/permission'

export const vPermission = {
  mounted(el, binding) {
    const store = usePermissionStore()
    
    const checkPermission = () => {
      const { value, modifiers, arg } = binding
      
      let hasAccess = false
      
      if (arg === 'role') {
        if (Array.isArray(value)) {
          hasAccess = modifiers.all
            ? value.every(role => store.hasRole(role))
            : store.hasAnyRole(value)
        } else {
          hasAccess = store.hasRole(value)
        }
      } else {
        if (Array.isArray(value)) {
          hasAccess = modifiers.all
            ? store.hasAllPermissions(value)
            : store.hasAnyPermission(value)
        } else {
          hasAccess = store.hasPermission(value)
        }
      }
      
      if (!hasAccess) {
        if (modifiers.hide) {
          el.style.display = 'none'
        } else if (modifiers.disable) {
          el.disabled = true
          el.classList.add('disabled')
          el.style.opacity = '0.5'
          el.style.cursor = 'not-allowed'
        } else {
          el.remove()
        }
      } else {
        if (modifiers.hide) {
          el.style.display = ''
        } else if (modifiers.disable) {
          el.disabled = false
          el.classList.remove('disabled')
          el.style.opacity = ''
          el.style.cursor = ''
        }
      }
    }
    
    checkPermission()
    
    el._permissionCheck = checkPermission
  },
  
  updated(el, binding) {
    if (el._permissionCheck) {
      el._permissionCheck()
    }
  },
  
  unmounted(el) {
    delete el._permissionCheck
  }
}

export default vPermission