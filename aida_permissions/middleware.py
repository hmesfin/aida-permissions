from django.contrib.auth.models import AnonymousUser

from .compat import MIDDLEWARE_MIXIN
from .utils.permissions import PermissionChecker


class PermissionMiddleware(MIDDLEWARE_MIXIN):
    def process_request(self, request):
        if not isinstance(request.user, AnonymousUser):
            request.permission_checker = PermissionChecker(request.user)

            tenant_id = self.get_tenant_id(request)
            if tenant_id:
                request.tenant_id = tenant_id
                request.permission_checker.set_tenant(tenant_id)
        else:
            request.permission_checker = None
            request.tenant_id = None

    def get_tenant_id(self, request):
        if hasattr(request, "tenant"):
            return request.tenant.id

        tenant_header = request.META.get("HTTP_X_TENANT_ID")
        if tenant_header:
            return tenant_header

        if hasattr(request, "session") and "tenant_id" in request.session:
            return request.session["tenant_id"]

        return None


class AuditMiddleware(MIDDLEWARE_MIXIN):
    def process_response(self, request, response):
        if hasattr(request, "permission_checks"):
            from .models.audit import PermissionAudit

            for check in request.permission_checks:
                PermissionAudit.objects.create(
                    user=request.user if not isinstance(request.user, AnonymousUser) else None,
                    permission_codename=check["permission"],
                    granted=check["granted"],
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    request_path=request.path,
                    request_method=request.method,
                    metadata=check.get("metadata", {}),
                )

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")
