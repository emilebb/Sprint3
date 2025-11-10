# clients/views.py
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponseForbidden, HttpResponseNotAllowed
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import Client, SecurityEvent
from .auth0backend import getRole
from django.shortcuts import render


def home(request):
    return render(request, 'index.html', {})

def _log(request, action, allowed, detail=""):
    try:
        from .middleware import ClientsSecurityMiddleware as M
        role = getRole(request) if request.user.is_authenticated else None
        SecurityEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            role=role or "",
            path=request.path,
            method=request.method,
            ip=M._client_ip(M, request),
            action=action,
            allowed=allowed,
            detail=detail,
        )
    except Exception:
        pass


def _require_admin(request):
    role = getRole(request)
    if role != "Admin":
        _log(request, "forbidden_role", False, f"role={role}")
        return False
    return True


@login_required
@require_http_methods(["GET"])
def clients_list(request):
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    data = list(Client.objects.values("id", "name", "email", "phone", "address", "document_id", "created_at"))
    _log(request, "list_clients", True)
    return JsonResponse({"results": data}, status=200)


@login_required
@require_http_methods(["GET"])
def client_detail(request, pk):
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    obj = get_object_or_404(Client, pk=pk)
    data = {
        "id": obj.id,
        "name": obj.name,
        "email": obj.email,
        "phone": obj.phone,
        "address": obj.address,
        "document_id": obj.document_id,
        "created_at": obj.created_at,
    }
    _log(request, "detail_client", True)
    return JsonResponse(data, status=200)

@login_required
@require_http_methods(["POST"])
def client_create(request):
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    # Validación estricta: no SQL crudo
    fields = ("name","email","phone","address","document_id")
    payload = {f: request.POST.get(f, "").strip() for f in fields}
    if not payload["name"] or not payload["email"] or not payload["document_id"]:
        _log(request, "create_client_invalid", False, "missing required fields")
        return JsonResponse({"detail": "Missing required fields."}, status=400)
    obj = Client.objects.create(**payload)
    _log(request, "create_client", True)
    return JsonResponse({"id": obj.id}, status=201)


@login_required
@require_http_methods(["POST","PUT","PATCH"])
def client_update(request, pk):
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    obj = get_object_or_404(Client, pk=pk)
    data = request.POST or request.PUT if hasattr(request, "PUT") else request.body
    updated = False
    for f in ("name","email","phone","address","document_id"):
        v = request.POST.get(f)
        if v is not None:
            setattr(obj, f, v.strip())
            updated = True
    if updated:
        obj.save()
        _log(request, "update_client", True)
        return JsonResponse({"detail": "updated"}, status=200)
    _log(request, "update_client_invalid", False, "no fields provided")
    return JsonResponse({"detail": "no fields provided"}, status=400)


@login_required
@require_http_methods(["DELETE"])
def client_delete(request, pk):
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    obj = get_object_or_404(Client, pk=pk)
    obj.delete()
    _log(request, "delete_client", True)
    return JsonResponse({"detail": "deleted"}, status=200)

@login_required
@require_http_methods(["GET"])
def security_report(request):
    """Métricas: ataques rechazados vs permitidos (objetivo: 100% rechazados sin fuga)."""
    if not _require_admin(request):
        return HttpResponseForbidden("Insufficient permissions.")
    total = SecurityEvent.objects.count()
    denied = SecurityEvent.objects.filter(allowed=False).count()
    allowed = SecurityEvent.objects.filter(allowed=True).count()
    by_action = (SecurityEvent.objects
                 .values("action")
                 .order_by("action")
                 .annotate(total=models.Count("id"),
                           denied=models.Count("id", filter=models.Q(allowed=False)),
                           allowed=models.Count("id", filter=models.Q(allowed=True))))
    return JsonResponse({
        "total_events": total,
        "denied": denied,
        "allowed": allowed,
        "by_action": list(by_action),
    }, status=200)