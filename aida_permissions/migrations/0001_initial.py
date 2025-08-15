# Generated migration file - compatible with Django 3.2 through 5.1

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid

try:
    from django.db.models import JSONField
except ImportError:
    from django.contrib.postgres.fields import JSONField


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PermissionCategory',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('name', models.CharField(max_length=100, unique=True)),
                ('display_name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('icon', models.CharField(blank=True, max_length=50)),
                ('order', models.IntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_created', to=settings.AUTH_USER_MODEL)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Permission Category',
                'verbose_name_plural': 'Permission Categories',
                'ordering': ['order', 'name'],
            },
        ),
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('codename', models.CharField(help_text='Unique identifier for the permission (e.g., "equipment.view")', max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('permission_type', models.CharField(choices=[('view', 'View'), ('create', 'Create'), ('edit', 'Edit'), ('delete', 'Delete'), ('export', 'Export'), ('import', 'Import'), ('approve', 'Approve'), ('reject', 'Reject'), ('custom', 'Custom')], default='custom', max_length=20)),
                ('resource', models.CharField(help_text='Resource this permission applies to (e.g., "equipment", "rental")', max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('is_system', models.BooleanField(default=False, help_text='System permissions cannot be deleted')),
                ('requires_object', models.BooleanField(default=False, help_text='Whether this permission requires object-level checking')),
                ('metadata', JSONField(blank=True, default=dict)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='permissions', to='aida_permissions.permissioncategory')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_created', to=settings.AUTH_USER_MODEL)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Permission',
                'verbose_name_plural': 'Permissions',
                'ordering': ['category', 'resource', 'permission_type'],
            },
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('name', models.CharField(max_length=100)),
                ('display_name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('role_type', models.CharField(choices=[('system', 'System'), ('custom', 'Custom'), ('template', 'Template')], default='custom', max_length=20)),
                ('is_active', models.BooleanField(default=True)),
                ('is_default', models.BooleanField(default=False, help_text='Automatically assigned to new users')),
                ('priority', models.IntegerField(default=0, help_text='Higher priority roles override lower ones')),
                ('metadata', JSONField(blank=True, default=dict)),
                ('max_users', models.IntegerField(blank=True, help_text='Maximum number of users that can have this role', null=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_created', to=settings.AUTH_USER_MODEL)),
                ('parent_role', models.ForeignKey(blank=True, help_text='Inherit permissions from parent role', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='child_roles', to='aida_permissions.role')),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Role',
                'verbose_name_plural': 'Roles',
                'ordering': ['-priority', 'name'],
            },
        ),
        migrations.CreateModel(
            name='UserRole',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('assigned_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('scope', JSONField(blank=True, default=dict, help_text='Scope limitations for this role assignment')),
                ('assigned_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='role_assignments_made', to=settings.AUTH_USER_MODEL)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_created', to=settings.AUTH_USER_MODEL)),
                ('role', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_assignments', to='aida_permissions.role')),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_updated', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_roles', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'User Role',
                'verbose_name_plural': 'User Roles',
                'ordering': ['-assigned_at'],
            },
        ),
        migrations.CreateModel(
            name='RolePermission',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tenant_id', models.CharField(blank=True, db_index=True, max_length=100, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('granted_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('conditions', JSONField(blank=True, default=dict, help_text='Additional conditions for this permission grant')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_created', to=settings.AUTH_USER_MODEL)),
                ('permission', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='aida_permissions.permission')),
                ('role', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='aida_permissions.role')),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(class)s_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Role Permission',
                'verbose_name_plural': 'Role Permissions',
            },
        ),
        migrations.AddField(
            model_name='role',
            name='permissions',
            field=models.ManyToManyField(related_name='roles', through='aida_permissions.RolePermission', to='aida_permissions.permission'),
        ),
        migrations.AddIndex(
            model_name='permission',
            index=models.Index(fields=['codename'], name='aida_permis_codenam_e8d3f1_idx'),
        ),
        migrations.AddIndex(
            model_name='permission',
            index=models.Index(fields=['resource', 'permission_type'], name='aida_permis_resourc_3d4e8a_idx'),
        ),
        migrations.AddIndex(
            model_name='permission',
            index=models.Index(fields=['is_active'], name='aida_permis_is_acti_0e3c3f_idx'),
        ),
        migrations.AddIndex(
            model_name='role',
            index=models.Index(fields=['is_active', 'is_default'], name='aida_permis_is_acti_7b5d8e_idx'),
        ),
        migrations.AddIndex(
            model_name='role',
            index=models.Index(fields=['tenant_id', 'name'], name='aida_permis_tenant__2a9d3f_idx'),
        ),
        migrations.AddIndex(
            model_name='rolepermission',
            index=models.Index(fields=['role', 'permission', 'is_active'], name='aida_permis_role_id_8f3d2e_idx'),
        ),
        migrations.AddIndex(
            model_name='userrole',
            index=models.Index(fields=['user', 'is_active'], name='aida_permis_user_id_3e8d2f_idx'),
        ),
        migrations.AddIndex(
            model_name='userrole',
            index=models.Index(fields=['role', 'is_active'], name='aida_permis_role_id_9f2d3e_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='userrole',
            unique_together={('user', 'role', 'tenant_id')},
        ),
        migrations.AlterUniqueTogether(
            name='rolepermission',
            unique_together={('role', 'permission')},
        ),
        migrations.AlterUniqueTogether(
            name='role',
            unique_together={('name', 'tenant_id')},
        ),
    ]