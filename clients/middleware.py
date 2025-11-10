# clients/middleware.py
from django.http import JsonResponse
from django.urls import resolve
from django.utils.deprecation import MiddlewareMixin
from .models import SecurityEvent
from .auth0backend import getRole

class ClientsSecurityMiddleware(MiddlewareMixin):
    """
    - Bloquea TODA solicitud no autenticada a /clients/*
    - Registra SecurityEvent (la clase creada en clients/models.py) para cada intento.
    """
    CLIENTS_PREFIX = "/clients/"

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.path.startswith(self.CLIENTS_PREFIX):
            return None

        role = None
        if request.user.is_authenticated:
            role = getRole(request)

        # Si no autenticado, bloquear y auditar
        if not request.user.is_authenticated:
            self._log(request, role, action="unauth_access", allowed=False, detail="not authenticated")
            return JsonResponse({"detail": "Authentication required."}, status=401)

        # Autenticado: 
        self._log(request, role, action="clients_hit", allowed=True, detail="authenticated hit")
        return None

    def _log(self, request, role, action, allowed, detail=""):
        try:
            SecurityEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                role=role or "",
                path=request.path,
                method=request.method,
                ip=self._client_ip(request),
                action=action,
                allowed=allowed,
                detail=detail,
            )
        except Exception:
            pass

    def _client_ip(self, request):
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
