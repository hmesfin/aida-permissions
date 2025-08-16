"""
Compatibility module for different Django versions.
Supports Django 3.2 through 5.1
"""

from django import VERSION as DJANGO_VERSION

# Django version checks
DJANGO_3_2 = DJANGO_VERSION >= (3, 2) and DJANGO_VERSION < (4, 0)
DJANGO_4_0 = DJANGO_VERSION >= (4, 0) and DJANGO_VERSION < (4, 1)
DJANGO_4_1 = DJANGO_VERSION >= (4, 1) and DJANGO_VERSION < (4, 2)
DJANGO_4_2 = DJANGO_VERSION >= (4, 2) and DJANGO_VERSION < (5, 0)
DJANGO_5_0 = DJANGO_VERSION >= (5, 0) and DJANGO_VERSION < (5, 1)
DJANGO_5_1 = DJANGO_VERSION >= (5, 1) and DJANGO_VERSION < (5, 2)

# Handle imports that changed between versions
if DJANGO_VERSION >= (4, 0):
    from django.utils.translation import gettext_lazy as _
else:
    from django.utils.translation import ugettext_lazy as _

# Handle changes in URL patterns
if DJANGO_VERSION >= (4, 0):
    from django.urls import path, re_path
else:
    from django.conf.urls import url as re_path
    from django.urls import path

# Handle admin site header changes
if DJANGO_VERSION >= (5, 0):
    def get_admin_header_template():
        return "admin/base_site.html"
else:
    def get_admin_header_template():
        return "admin/base_site.html"

# Handle JSONField compatibility
if DJANGO_VERSION >= (3, 2):
    from django.db.models import JSONField
else:
    try:
        from django.contrib.postgres.fields import JSONField
    except ImportError:
        # Fallback for SQLite
        from django.db.models import TextField as JSONField

# Handle default auto field
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField" if DJANGO_VERSION >= (3, 2) else "django.db.models.AutoField"

# Handle middleware class vs function-based middleware
# MiddlewareMixin is available in all Django versions we support
from django.utils.deprecation import MiddlewareMixin

MIDDLEWARE_MIXIN = MiddlewareMixin

# Handle force_text/force_str changes
if DJANGO_VERSION >= (4, 0):
    from django.utils.encoding import force_str
    force_text = force_str
else:
    from django.utils.encoding import force_text
    force_str = force_text

# Handle URL namespace changes
if DJANGO_VERSION >= (4, 0):
    def include_with_namespace(urls, namespace):
        from django.urls import include
        return include((urls, namespace), namespace=namespace)
else:
    def include_with_namespace(urls, namespace):
        from django.conf.urls import include
        return include(urls, namespace=namespace)

# Cache delete pattern compatibility
def cache_delete_pattern(pattern):
    """
    Delete cache keys matching a pattern.
    Compatible across Django versions.
    """
    from django.core.cache import cache

    if hasattr(cache, "delete_pattern"):
        # Redis cache backend
        cache.delete_pattern(pattern)
    elif hasattr(cache, "delete_many"):
        # Django 3.2+ with delete_many
        if hasattr(cache, "keys"):
            keys = cache.keys(pattern)
            if keys:
                cache.delete_many(keys)
    else:
        # Fallback - clear all cache
        cache.clear()

# Compatibility for timezone
if DJANGO_VERSION >= (4, 0):
    from django.utils import timezone
    USE_TZ_DEFAULT = True
else:
    from django.utils import timezone
    USE_TZ_DEFAULT = False

# Admin compatibility
if DJANGO_VERSION >= (4, 0):
    def get_admin_urls():
        from django.contrib import admin
        return admin.site.urls
else:
    def get_admin_urls():
        from django.contrib import admin
        return admin.site.urls

# Model field compatibility
if DJANGO_VERSION >= (5, 0):
    def get_related_name(field):
        return field.remote_field.related_name
else:
    def get_related_name(field):
        return field.remote_field.related_name if hasattr(field, "remote_field") else field.related_name

# Async support compatibility
HAS_ASYNC_SUPPORT = DJANGO_VERSION >= (4, 1)

__all__ = [
    "DEFAULT_AUTO_FIELD",
    "DJANGO_VERSION",
    "HAS_ASYNC_SUPPORT",
    "MIDDLEWARE_MIXIN",
    "USE_TZ_DEFAULT",
    "JSONField",
    "_",
    "cache_delete_pattern",
    "force_str",
    "force_text",
    "get_admin_urls",
    "get_related_name",
    "include_with_namespace",
    "path",
    "re_path",
    "timezone",
]
