<template>
  <div class="role-manager">
    <div class="header">
      <h2>Role Management</h2>
      <button 
        v-if="canCreate"
        @click="showCreateDialog = true"
        class="btn btn-primary"
      >
        Create Role
      </button>
    </div>

    <div v-if="loading" class="loading">
      Loading roles...
    </div>

    <div v-else-if="error" class="error">
      {{ error }}
    </div>

    <div v-else class="roles-grid">
      <div
        v-for="role in roles"
        :key="role.id"
        class="role-card"
      >
        <div class="role-header">
          <h3>{{ role.display_name }}</h3>
          <span class="role-type" :class="`type-${role.role_type}`">
            {{ role.role_type }}
          </span>
        </div>
        
        <p class="role-description">{{ role.description }}</p>
        
        <div class="role-stats">
          <div class="stat">
            <span class="label">Users:</span>
            <span class="value">{{ role.user_count }}</span>
          </div>
          <div class="stat">
            <span class="label">Permissions:</span>
            <span class="value">{{ role.permission_count }}</span>
          </div>
          <div class="stat">
            <span class="label">Priority:</span>
            <span class="value">{{ role.priority }}</span>
          </div>
        </div>

        <div class="role-actions">
          <button
            @click="viewRole(role)"
            class="btn btn-sm btn-secondary"
          >
            View
          </button>
          <button
            v-if="canEdit && role.role_type !== 'system'"
            @click="editRole(role)"
            class="btn btn-sm btn-primary"
          >
            Edit
          </button>
          <button
            v-if="canDelete && role.role_type === 'custom'"
            @click="deleteRole(role)"
            class="btn btn-sm btn-danger"
          >
            Delete
          </button>
        </div>
      </div>
    </div>

    <RoleDialog
      v-if="showCreateDialog || showEditDialog"
      :role="selectedRole"
      :mode="showCreateDialog ? 'create' : 'edit'"
      @save="handleSave"
      @close="closeDialogs"
    />

    <RoleDetailsDialog
      v-if="showViewDialog"
      :role="selectedRole"
      @close="showViewDialog = false"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import axios from 'axios'
import { usePermissions } from '../composables/usePermissions'
import RoleDialog from './RoleDialog.vue'
import RoleDetailsDialog from './RoleDetailsDialog.vue'

const { hasPermission } = usePermissions()

const roles = ref([])
const loading = ref(false)
const error = ref(null)
const showCreateDialog = ref(false)
const showEditDialog = ref(false)
const showViewDialog = ref(false)
const selectedRole = ref(null)

const apiBaseUrl = import.meta.env.VITE_API_URL || '/api'

const canCreate = computed(() => hasPermission('role.create'))
const canEdit = computed(() => hasPermission('role.edit'))
const canDelete = computed(() => hasPermission('role.delete'))

const fetchRoles = async () => {
  loading.value = true
  error.value = null
  
  try {
    const response = await axios.get(`${apiBaseUrl}/roles/`)
    roles.value = response.data
  } catch (err) {
    error.value = 'Failed to load roles'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const viewRole = (role) => {
  selectedRole.value = role
  showViewDialog.value = true
}

const editRole = (role) => {
  selectedRole.value = role
  showEditDialog.value = true
}

const deleteRole = async (role) => {
  if (!confirm(`Are you sure you want to delete the role "${role.display_name}"?`)) {
    return
  }
  
  try {
    await axios.delete(`${apiBaseUrl}/roles/${role.id}/`)
    roles.value = roles.value.filter(r => r.id !== role.id)
  } catch (err) {
    alert('Failed to delete role')
    console.error(err)
  }
}

const handleSave = async (roleData) => {
  try {
    if (showCreateDialog.value) {
      const response = await axios.post(`${apiBaseUrl}/roles/`, roleData)
      roles.value.push(response.data)
    } else {
      const response = await axios.patch(
        `${apiBaseUrl}/roles/${selectedRole.value.id}/`,
        roleData
      )
      const index = roles.value.findIndex(r => r.id === selectedRole.value.id)
      if (index !== -1) {
        roles.value[index] = response.data
      }
    }
    closeDialogs()
  } catch (err) {
    alert('Failed to save role')
    console.error(err)
  }
}

const closeDialogs = () => {
  showCreateDialog.value = false
  showEditDialog.value = false
  selectedRole.value = null
}

onMounted(() => {
  fetchRoles()
})
</script>

<style scoped>
.role-manager {
  padding: 1.5rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

.loading,
.error {
  padding: 2rem;
  text-align: center;
}

.error {
  color: #dc2626;
}

.roles-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}

.role-card {
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.role-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.role-header h3 {
  margin: 0;
  font-size: 1.25rem;
}

.role-type {
  padding: 0.25rem 0.5rem;
  border-radius: 0.25rem;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.type-system {
  background: #fee2e2;
  color: #dc2626;
}

.type-custom {
  background: #dbeafe;
  color: #2563eb;
}

.type-template {
  background: #f3e8ff;
  color: #9333ea;
}

.role-description {
  color: #6b7280;
  margin-bottom: 1rem;
}

.role-stats {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
  padding: 1rem;
  background: #f9fafb;
  border-radius: 0.25rem;
}

.stat {
  display: flex;
  flex-direction: column;
}

.stat .label {
  font-size: 0.75rem;
  color: #6b7280;
}

.stat .value {
  font-size: 1.125rem;
  font-weight: 600;
}

.role-actions {
  display: flex;
  gap: 0.5rem;
}

.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 0.375rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: #2563eb;
  color: white;
}

.btn-primary:hover {
  background: #1d4ed8;
}

.btn-secondary {
  background: #6b7280;
  color: white;
}

.btn-secondary:hover {
  background: #4b5563;
}

.btn-danger {
  background: #dc2626;
  color: white;
}

.btn-danger:hover {
  background: #b91c1c;
}

.btn-sm {
  padding: 0.25rem 0.75rem;
  font-size: 0.875rem;
}
</style>