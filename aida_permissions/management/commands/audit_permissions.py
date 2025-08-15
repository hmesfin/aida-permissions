from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from datetime import datetime, timedelta
from aida_permissions.models import UserRole, Role, Permission

User = get_user_model()


class Command(BaseCommand):
    help = 'Audit permissions and roles usage'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user',
            type=str,
            help='Username or email to audit specific user'
        )
        parser.add_argument(
            '--role',
            type=str,
            help='Role name to audit'
        )
        parser.add_argument(
            '--permission',
            type=str,
            help='Permission codename to audit'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to look back for recent assignments'
        )
        parser.add_argument(
            '--tenant-id',
            type=str,
            help='Tenant ID for multi-tenant setup'
        )

    def handle(self, *args, **options):
        user_filter = options.get('user')
        role_filter = options.get('role')
        permission_filter = options.get('permission')
        days = options.get('days')
        tenant_id = options.get('tenant_id')

        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(self.style.SUCCESS('PERMISSION AUDIT REPORT'))
        self.stdout.write(self.style.SUCCESS('=' * 60))

        if user_filter:
            self.audit_user(user_filter, tenant_id)
        elif role_filter:
            self.audit_role(role_filter, tenant_id)
        elif permission_filter:
            self.audit_permission(permission_filter, tenant_id)
        else:
            self.general_audit(days, tenant_id)

    def audit_user(self, user_identifier, tenant_id):
        try:
            user = User.objects.get(Q(username=user_identifier) | Q(email=user_identifier))
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User not found: {user_identifier}'))
            return

        self.stdout.write(f'\nUser: {user.username} ({user.email})')
        self.stdout.write('-' * 40)

        user_roles = UserRole.objects.filter(user=user, is_active=True)
        if tenant_id:
            user_roles = user_roles.filter(Q(tenant_id=tenant_id) | Q(tenant_id__isnull=True))

        self.stdout.write(f'\nActive Roles ({user_roles.count()}):')
        for user_role in user_roles:
            expires = f" (expires: {user_role.expires_at})" if user_role.expires_at else ""
            self.stdout.write(f'  - {user_role.role.display_name}{expires}')

        from aida_permissions.utils import PermissionChecker
        checker = PermissionChecker(user, tenant_id)
        permissions = checker.get_user_permissions()

        self.stdout.write(f'\nTotal Permissions: {len(permissions)}')
        
        by_resource = {}
        for perm in permissions:
            resource = perm.split('.')[0] if '.' in perm else 'other'
            if resource not in by_resource:
                by_resource[resource] = []
            by_resource[resource].append(perm)

        for resource, perms in sorted(by_resource.items()):
            self.stdout.write(f'\n  {resource.upper()}:')
            for perm in sorted(perms):
                self.stdout.write(f'    - {perm}')

    def audit_role(self, role_name, tenant_id):
        try:
            role = Role.objects.get(name=role_name)
        except Role.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Role not found: {role_name}'))
            return

        self.stdout.write(f'\nRole: {role.display_name}')
        self.stdout.write(f'Type: {role.role_type}')
        self.stdout.write(f'Priority: {role.priority}')
        self.stdout.write(f'Active: {role.is_active}')
        self.stdout.write(f'Default: {role.is_default}')
        self.stdout.write('-' * 40)

        permissions = role.get_all_permissions(include_inherited=True)
        self.stdout.write(f'\nPermissions ({permissions.count()}):')
        for perm in permissions:
            self.stdout.write(f'  - {perm.codename}: {perm.name}')

        user_count = UserRole.objects.filter(role=role, is_active=True).count()
        self.stdout.write(f'\nAssigned to {user_count} users')

        if user_count <= 10:
            users = UserRole.objects.filter(role=role, is_active=True).select_related('user')
            self.stdout.write('\nUsers:')
            for user_role in users:
                self.stdout.write(f'  - {user_role.user.username}')

    def audit_permission(self, permission_codename, tenant_id):
        try:
            permission = Permission.objects.get(codename=permission_codename)
        except Permission.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'Permission not found: {permission_codename}'))
            return

        self.stdout.write(f'\nPermission: {permission.name}')
        self.stdout.write(f'Codename: {permission.codename}')
        self.stdout.write(f'Type: {permission.permission_type}')
        self.stdout.write(f'Resource: {permission.resource}')
        self.stdout.write(f'System: {permission.is_system}')
        self.stdout.write('-' * 40)

        roles = Role.objects.filter(
            permissions=permission,
            rolepermission__is_active=True
        ).distinct()

        self.stdout.write(f'\nRoles with this permission ({roles.count()}):')
        for role in roles:
            user_count = role.user_assignments.filter(is_active=True).count()
            self.stdout.write(f'  - {role.display_name} ({user_count} users)')

        total_users = UserRole.objects.filter(
            role__in=roles,
            is_active=True
        ).values('user').distinct().count()

        self.stdout.write(f'\nTotal users with this permission: {total_users}')

    def general_audit(self, days, tenant_id):
        cutoff_date = datetime.now() - timedelta(days=days)

        self.stdout.write('\nSYSTEM OVERVIEW')
        self.stdout.write('-' * 40)

        filters = {}
        if tenant_id:
            filters['tenant_id'] = tenant_id

        total_users = User.objects.filter(is_active=True).count()
        total_roles = Role.objects.filter(is_active=True, **filters).count()
        total_permissions = Permission.objects.filter(is_active=True, **filters).count()
        total_assignments = UserRole.objects.filter(is_active=True, **filters).count()

        self.stdout.write(f'Active Users: {total_users}')
        self.stdout.write(f'Active Roles: {total_roles}')
        self.stdout.write(f'Active Permissions: {total_permissions}')
        self.stdout.write(f'Active Role Assignments: {total_assignments}')

        self.stdout.write('\nROLE DISTRIBUTION')
        self.stdout.write('-' * 40)

        role_stats = UserRole.objects.filter(
            is_active=True,
            **filters
        ).values(
            'role__display_name'
        ).annotate(
            count=Count('user', distinct=True)
        ).order_by('-count')

        for stat in role_stats[:10]:
            self.stdout.write(f"{stat['role__display_name']}: {stat['count']} users")

        self.stdout.write(f'\nRECENT ASSIGNMENTS (last {days} days)')
        self.stdout.write('-' * 40)

        recent = UserRole.objects.filter(
            assigned_at__gte=cutoff_date,
            **filters
        ).select_related('user', 'role', 'assigned_by')[:10]

        for assignment in recent:
            assigned_by = assignment.assigned_by.username if assignment.assigned_by else 'System'
            self.stdout.write(
                f"{assignment.assigned_at.strftime('%Y-%m-%d')}: "
                f"{assignment.user.username} -> {assignment.role.display_name} "
                f"(by {assigned_by})"
            )

        self.stdout.write('\nEXPIRING ASSIGNMENTS')
        self.stdout.write('-' * 40)

        expiring = UserRole.objects.filter(
            expires_at__isnull=False,
            expires_at__lte=datetime.now() + timedelta(days=30),
            is_active=True,
            **filters
        ).select_related('user', 'role')[:10]

        if expiring:
            for assignment in expiring:
                days_left = (assignment.expires_at - datetime.now()).days
                self.stdout.write(
                    f"{assignment.user.username}: {assignment.role.display_name} "
                    f"(expires in {days_left} days)"
                )
        else:
            self.stdout.write('No assignments expiring in the next 30 days')

        self.stdout.write('\nUNUSED PERMISSIONS')
        self.stdout.write('-' * 40)

        used_permissions = set(
            Permission.objects.filter(
                roles__user_assignments__is_active=True,
                **filters
            ).values_list('id', flat=True)
        )

        unused = Permission.objects.filter(
            is_active=True,
            **filters
        ).exclude(id__in=used_permissions)

        if unused:
            for perm in unused[:20]:
                self.stdout.write(f'  - {perm.codename}')
            if unused.count() > 20:
                self.stdout.write(f'  ... and {unused.count() - 20} more')
        else:
            self.stdout.write('All permissions are in use')