<template>
  <div v-if="hasAccess">
    <slot />
  </div>
  <div v-else-if="showFallback">
    <slot name="fallback">
      <div class="permission-denied">
        {{ fallbackMessage }}
      </div>
    </slot>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { usePermissions } from '../composables/usePermissions'

const props = defineProps({
  permission: {
    type: [String, Array],
    default: null
  },
  role: {
    type: [String, Array],
    default: null
  },
  requireAll: {
    type: Boolean,
    default: false
  },
  showFallback: {
    type: Boolean,
    default: false
  },
  fallbackMessage: {
    type: String,
    default: 'You do not have permission to view this content.'
  }
})

const { hasPermission, hasAllPermissions, hasAnyPermission, hasRole, hasAnyRole } = usePermissions()

const hasAccess = computed(() => {
  if (!props.permission && !props.role) {
    return true
  }
  
  let permissionCheck = true
  let roleCheck = true
  
  if (props.permission) {
    if (Array.isArray(props.permission)) {
      permissionCheck = props.requireAll 
        ? hasAllPermissions(props.permission)
        : hasAnyPermission(props.permission)
    } else {
      permissionCheck = hasPermission(props.permission)
    }
  }
  
  if (props.role) {
    if (Array.isArray(props.role)) {
      roleCheck = props.requireAll
        ? props.role.every(r => hasRole(r))
        : hasAnyRole(props.role)
    } else {
      roleCheck = hasRole(props.role)
    }
  }
  
  return permissionCheck && roleCheck
})
</script>

<style scoped>
.permission-denied {
  padding: 1rem;
  background-color: #f3f4f6;
  border: 1px solid #d1d5db;
  border-radius: 0.375rem;
  color: #6b7280;
  text-align: center;
}
</style>