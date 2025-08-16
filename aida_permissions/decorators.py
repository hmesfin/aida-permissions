import contextlib
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from .compat import _


def require_permission(permission_codenames, raise_exception=True, redirect_url=None, message=None):
    if isinstance(permission_codenames, str):
        permission_codenames = [permission_codenames]

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not hasattr(request, "permission_checker") or not request.permission_checker:
                if raise_exception:
                    raise PermissionDenied(_("Permission checker not available"))
                messages.error(request, message or _("You don't have permission to access this resource"))
                return redirect(redirect_url or settings.LOGIN_URL)

            for permission in permission_codenames:
                if not request.permission_checker.has_permission(permission):
                    if not hasattr(request, "permission_checks"):
                        request.permission_checks = []
                    request.permission_checks.append({
                        "permission": permission,
                        "granted": False,
                        "metadata": {"view": view_func.__name__},
                    })

                    if raise_exception:
                        raise PermissionDenied(
                            _("You don't have the required permission: %(permission)s") % {"permission": permission},
                        )
                    messages.error(
                        request,
                        message or _("You don't have the required permission: %(permission)s") % {"permission": permission},
                    )
                    return redirect(redirect_url or settings.LOGIN_URL)

            if not hasattr(request, "permission_checks"):
                request.permission_checks = []
            for permission in permission_codenames:
                request.permission_checks.append({
                    "permission": permission,
                    "granted": True,
                    "metadata": {"view": view_func.__name__},
                })

            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator


def require_any_permission(permission_codenames, raise_exception=True, redirect_url=None, message=None):
    if isinstance(permission_codenames, str):
        permission_codenames = [permission_codenames]

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not hasattr(request, "permission_checker") or not request.permission_checker:
                if raise_exception:
                    raise PermissionDenied(_("Permission checker not available"))
                messages.error(request, message or _("You don't have permission to access this resource"))
                return redirect(redirect_url or settings.LOGIN_URL)

            has_any = False
            for permission in permission_codenames:
                if request.permission_checker.has_permission(permission):
                    has_any = True
                    break

            if not hasattr(request, "permission_checks"):
                request.permission_checks = []

            for permission in permission_codenames:
                request.permission_checks.append({
                    "permission": permission,
                    "granted": has_any,
                    "metadata": {"view": view_func.__name__, "any_of": True},
                })

            if not has_any:
                if raise_exception:
                    raise PermissionDenied(
                        _("You need at least one of these permissions: %(permissions)s") % {
                            "permissions": ", ".join(permission_codenames),
                        },
                    )
                messages.error(
                    request,
                    message or _("You need at least one of these permissions: %(permissions)s") % {
                        "permissions": ", ".join(permission_codenames),
                    },
                )
                return redirect(redirect_url or settings.LOGIN_URL)

            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator


def require_object_permission(permission_codename, obj_param="pk", model=None, raise_exception=True):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not hasattr(request, "permission_checker") or not request.permission_checker:
                if raise_exception:
                    raise PermissionDenied(_("Permission checker not available"))
                messages.error(request, _("You don't have permission to access this resource"))
                return redirect(settings.LOGIN_URL)

            obj = None
            if model:
                obj_id = kwargs.get(obj_param) or request.GET.get(obj_param)
                if obj_id:
                    with contextlib.suppress(model.DoesNotExist):
                        obj = model.objects.get(pk=obj_id)

            if not request.permission_checker.has_object_permission(permission_codename, obj):
                if not hasattr(request, "permission_checks"):
                    request.permission_checks = []
                request.permission_checks.append({
                    "permission": permission_codename,
                    "granted": False,
                    "metadata": {
                        "view": view_func.__name__,
                        "object": str(obj) if obj else None,
                        "object_type": "object_permission",
                    },
                })

                if raise_exception:
                    raise PermissionDenied(
                        _("You don't have permission to access this object"),
                    )
                messages.error(request, _("You don't have permission to access this object"))
                return redirect(settings.LOGIN_URL)

            if not hasattr(request, "permission_checks"):
                request.permission_checks = []
            request.permission_checks.append({
                "permission": permission_codename,
                "granted": True,
                "metadata": {
                    "view": view_func.__name__,
                    "object": str(obj) if obj else None,
                    "object_type": "object_permission",
                },
            })

            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator


def permission_required_or_403(permission_codenames):
    return require_permission(permission_codenames, raise_exception=True)


def permission_required_or_login(permission_codenames, redirect_url=None, message=None):
    return require_permission(permission_codenames, raise_exception=False, redirect_url=redirect_url, message=message)
