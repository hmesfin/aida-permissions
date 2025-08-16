# Django Version Compatibility Guide

## Supported Django Versions

AIDA Permissions is compatible with Django versions 3.2 through 5.1, providing consistent functionality across all supported versions.

### Version Matrix

| Django Version | Python Version | Support Status |
|---------------|---------------|----------------|
| 5.1.x         | 3.10, 3.11, 3.12 | ✅ Fully Supported |
| 5.0.x         | 3.10, 3.11, 3.12 | ✅ Fully Supported |
| 4.2.x (LTS)   | 3.8, 3.9, 3.10, 3.11 | ✅ Fully Supported |
| 4.1.x         | 3.8, 3.9, 3.10, 3.11 | ✅ Fully Supported |
| 4.0.x         | 3.8, 3.9, 3.10 | ✅ Fully Supported |
| 3.2.x (LTS)   | 3.8, 3.9, 3.10 | ✅ Fully Supported |

## Compatibility Features

### 1. JSONField Support

The extension automatically handles JSONField compatibility:

- **Django 3.2+**: Uses native `django.db.models.JSONField`
- **Django < 3.2**: Falls back to `django.contrib.postgres.fields.JSONField` or TextField

```python
# Automatically handled by the compatibility layer
from aida_permissions.compat import JSONField

class MyModel(models.Model):
    metadata = JSONField(default=dict, blank=True)
```

### 2. Translation Support

Translation functions are normalized across versions:

- **Django 4.0+**: Uses `gettext_lazy`
- **Django < 4.0**: Uses `ugettext_lazy`

```python
# Works across all versions
from aida_permissions.compat import _

verbose_name = _('Permission')
```

### 3. Middleware Compatibility

Middleware works with both class-based and function-based approaches:

```python
# Automatically compatible
from aida_permissions.compat import MIDDLEWARE_MIXIN

class PermissionMiddleware(MIDDLEWARE_MIXIN):
    def process_request(self, request):
        # Your code here
```

### 4. Cache Operations

Cache pattern deletion is handled gracefully:

```python
from aida_permissions.compat import cache_delete_pattern

# Works with Redis cache or falls back gracefully
cache_delete_pattern('permission:*')
```

### 5. URL Patterns

URL configuration works across all versions:

```python
from aida_permissions.compat import path, re_path

urlpatterns = [
    path('api/', include('aida_permissions.urls')),
    re_path(r'^legacy/', legacy_view),
]
```

## Installation by Django Version

### Django 5.1.x

```bash
pip install "Django>=5.1,<5.2"
pip install aida-permissions
```

### Django 5.0.x

```bash
pip install "Django>=5.0,<5.1"
pip install aida-permissions
```

### Django 4.2.x (LTS)

```bash
pip install "Django>=4.2,<5.0"
pip install aida-permissions
```

### Django 3.2.x (LTS)

```bash
pip install "Django>=3.2,<4.0"
pip install aida-permissions
```

## Settings Configuration

### Django 5.x Settings

```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'aida_permissions',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'aida_permissions.middleware.PermissionMiddleware',
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
```

### Django 3.2.x Settings

```python
INSTALLED_APPS = [
    # Same as above
]

MIDDLEWARE = [
    # Same as above
]

# For Django 3.2
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True  # Explicitly set
```

## Migration Compatibility

Migrations are generated to be compatible across all supported versions:

```bash
# Works on all versions
python manage.py migrate aida_permissions
```

## Testing Across Versions

To test your application with different Django versions:

```bash
# Test with Django 5.1
pip install "Django>=5.1,<5.2"
pytest

# Test with Django 4.2 LTS
pip install "Django>=4.2,<5.0"
pytest

# Test with Django 3.2 LTS
pip install "Django>=3.2,<4.0"
pytest
```

## Custom User Model Support

AIDA Permissions fully supports custom Django User models with various configurations:

### Email-based Authentication

For User models using email as the primary identifier:

```python
# Custom User model
class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    # ... other fields
```

AIDA Permissions automatically detects and adapts to this configuration:
- Admin search fields adjust to use email
- Management commands accept email identifiers
- User displays show email when username is not available

### Models Without Username Field

For User models that don't have a username field:

```python
# Custom User model without username
class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    USERNAME_FIELD = 'email'
    # No username field
```

The extension handles this gracefully:
- No assumptions about username field existence
- Fallback to email or user ID for identification
- Dynamic field detection for admin and API

### Custom Authentication Fields

For User models with custom authentication fields:

```python
# Custom User model with unique identifier
class User(AbstractBaseUser):
    employee_id = models.CharField(unique=True, max_length=20)
    USERNAME_FIELD = 'employee_id'
    # ... other fields
```

Works seamlessly with any USERNAME_FIELD configuration.

## Known Compatibility Issues

### 1. Async Views (Django 4.1+)

Async view support is available only in Django 4.1+:

```python
from aida_permissions.compat import HAS_ASYNC_SUPPORT

if HAS_ASYNC_SUPPORT:
    async def my_async_view(request):
        # Async code here
else:
    def my_async_view(request):
        # Sync fallback
```

### 2. Redis Cache Backend

For optimal performance with cache pattern deletion, use Redis:

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

### 3. PostgreSQL JSONField

For Django < 3.2 with PostgreSQL:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        # ... other settings
    }
}
```

## Upgrading Django Versions

When upgrading Django versions:

1. **Update requirements.txt**:
   ```
   Django>=4.2,<5.0  # From
   Django>=5.0,<5.1  # To
   ```

2. **Run migrations**:
   ```bash
   python manage.py migrate
   ```

3. **Run tests**:
   ```bash
   python manage.py test
   pytest
   ```

4. **Clear cache**:
   ```python
   from django.core.cache import cache
   cache.clear()
   ```

## Support

For version-specific issues:

1. Check the [compatibility module](aida_permissions/compat.py)
2. Review [Django release notes](https://docs.djangoproject.com/en/stable/releases/)
3. Open an issue on [GitHub](https://github.com/hmesfin/aida-permissions/issues)

## Future Django Versions

The extension is designed to be forward-compatible. When new Django versions are released:

1. The compatibility layer will be updated
2. New features will be added while maintaining backward compatibility
3. Deprecation warnings will be addressed proactively

## Contributing

When contributing code:

1. Ensure compatibility with all supported Django versions
2. Use the compatibility module for version-specific features
3. Add tests for each supported Django version
4. Update this documentation for new compatibility considerations