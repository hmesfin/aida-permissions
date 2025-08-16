from django.core.management.base import BaseCommand
from django.db import transaction

from aida_permissions.models import Permission, PermissionCategory, Role


class Command(BaseCommand):
    help = "Initialize default permissions and roles"

    def add_arguments(self, parser):
        parser.add_argument(
            "--tenant-id",
            type=str,
            help="Tenant ID for multi-tenant setup",
        )
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear existing permissions before initializing",
        )

    def handle(self, *args, **options):
        tenant_id = options.get("tenant_id")
        clear = options.get("clear")

        with transaction.atomic():
            if clear:
                self.stdout.write("Clearing existing permissions...")
                Permission.objects.filter(is_system=False).delete()
                PermissionCategory.objects.filter(tenant_id=tenant_id).delete()
                Role.objects.filter(role_type="custom", tenant_id=tenant_id).delete()

            self.stdout.write("Creating permission categories...")
            categories = self.create_categories(tenant_id)

            self.stdout.write("Creating permissions...")
            permissions = self.create_permissions(categories, tenant_id)

            self.stdout.write("Creating default roles...")
            roles = self.create_roles(permissions, tenant_id)

            self.stdout.write(self.style.SUCCESS(
                f"Successfully initialized {len(permissions)} permissions and {len(roles)} roles",
            ))

    def create_categories(self, tenant_id):
        categories_data = [
            {
                "name": "equipment",
                "display_name": "Equipment Management",
                "description": "Permissions for managing equipment",
                "icon": "tool",
                "order": 1,
            },
            {
                "name": "rentals",
                "display_name": "Rental Management",
                "description": "Permissions for managing rentals",
                "icon": "calendar",
                "order": 2,
            },
            {
                "name": "users",
                "display_name": "User Management",
                "description": "Permissions for managing users",
                "icon": "users",
                "order": 3,
            },
            {
                "name": "roles",
                "display_name": "Role Management",
                "description": "Permissions for managing roles and permissions",
                "icon": "shield",
                "order": 4,
            },
            {
                "name": "reports",
                "display_name": "Reports",
                "description": "Permissions for accessing reports",
                "icon": "chart",
                "order": 5,
            },
            {
                "name": "settings",
                "display_name": "Settings",
                "description": "Permissions for system settings",
                "icon": "settings",
                "order": 6,
            },
        ]

        categories = {}
        for cat_data in categories_data:
            if tenant_id:
                cat_data["tenant_id"] = tenant_id
            category, created = PermissionCategory.objects.get_or_create(
                name=cat_data["name"],
                defaults=cat_data,
            )
            categories[category.name] = category
            if created:
                self.stdout.write(f"  Created category: {category.display_name}")

        return categories

    def create_permissions(self, categories, tenant_id):
        permissions_data = {
            "equipment": [
                ("equipment.view", "View Equipment", "view"),
                ("equipment.create", "Create Equipment", "create"),
                ("equipment.edit", "Edit Equipment", "edit"),
                ("equipment.delete", "Delete Equipment", "delete"),
                ("equipment.export", "Export Equipment Data", "export"),
                ("equipment.import", "Import Equipment Data", "import"),
            ],
            "rentals": [
                ("rental.view", "View Rentals", "view"),
                ("rental.create", "Create Rental", "create"),
                ("rental.edit", "Edit Rental", "edit"),
                ("rental.delete", "Delete Rental", "delete"),
                ("rental.approve", "Approve Rental", "approve"),
                ("rental.reject", "Reject Rental", "reject"),
                ("rental.cancel", "Cancel Rental", "custom"),
                ("rental.export", "Export Rental Data", "export"),
            ],
            "users": [
                ("user.view", "View Users", "view"),
                ("user.create", "Create User", "create"),
                ("user.edit", "Edit User", "edit"),
                ("user.delete", "Delete User", "delete"),
                ("user.activate", "Activate/Deactivate User", "custom"),
                ("user.reset_password", "Reset User Password", "custom"),
            ],
            "roles": [
                ("role.view", "View Roles", "view"),
                ("role.create", "Create Role", "create"),
                ("role.edit", "Edit Role", "edit"),
                ("role.delete", "Delete Role", "delete"),
                ("role.assign", "Assign Role to User", "custom"),
                ("permission.view", "View Permissions", "view"),
                ("permission.edit", "Edit Permissions", "edit"),
            ],
            "reports": [
                ("report.view", "View Reports", "view"),
                ("report.export", "Export Reports", "export"),
                ("report.schedule", "Schedule Reports", "custom"),
            ],
            "settings": [
                ("settings.view", "View Settings", "view"),
                ("settings.edit", "Edit Settings", "edit"),
                ("settings.backup", "Backup System", "custom"),
                ("settings.restore", "Restore System", "custom"),
            ],
        }

        all_permissions = []
        for category_name, perms in permissions_data.items():
            category = categories.get(category_name)
            if not category:
                continue

            for codename, name, perm_type in perms:
                resource = codename.split(".")[0]
                perm_data = {
                    "codename": codename,
                    "name": name,
                    "category": category,
                    "permission_type": perm_type,
                    "resource": resource,
                    "is_system": True,
                    "is_active": True,
                }
                if tenant_id:
                    perm_data["tenant_id"] = tenant_id

                permission, created = Permission.objects.get_or_create(
                    codename=codename,
                    defaults=perm_data,
                )
                all_permissions.append(permission)
                if created:
                    self.stdout.write(f"  Created permission: {codename}")

        return all_permissions

    def create_roles(self, permissions, tenant_id):
        roles_data = [
            {
                "name": "super_admin",
                "display_name": "Super Administrator",
                "description": "Full system access",
                "role_type": "system",
                "priority": 100,
                "permissions": permissions,
            },
            {
                "name": "admin",
                "display_name": "Administrator",
                "description": "Administrative access",
                "role_type": "system",
                "priority": 90,
                "permissions": [p for p in permissions if not p.codename.startswith("settings.")],
            },
            {
                "name": "manager",
                "display_name": "Manager",
                "description": "Management access",
                "role_type": "system",
                "priority": 70,
                "permissions": [p for p in permissions if p.permission_type in ["view", "create", "edit", "approve", "reject"]],
            },
            {
                "name": "staff",
                "display_name": "Staff",
                "description": "Staff member access",
                "role_type": "system",
                "priority": 50,
                "permissions": [p for p in permissions if p.permission_type in ["view", "create", "edit"] and p.resource in ["equipment", "rental"]],
            },
            {
                "name": "customer",
                "display_name": "Customer",
                "description": "Customer access",
                "role_type": "system",
                "priority": 30,
                "is_default": True,
                "permissions": [p for p in permissions if p.codename in ["equipment.view", "rental.view", "rental.create"]],
            },
        ]

        created_roles = []
        for role_data in roles_data:
            role_permissions = role_data.pop("permissions", [])

            if tenant_id:
                role_data["tenant_id"] = tenant_id

            role, created = Role.objects.get_or_create(
                name=role_data["name"],
                defaults=role_data,
            )

            if created:
                for permission in role_permissions:
                    role.add_permission(permission)
                self.stdout.write(f"  Created role: {role.display_name} with {len(role_permissions)} permissions")

            created_roles.append(role)

        return created_roles
