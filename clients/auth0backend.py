# clients/auth0backend.py
from django.conf import settings

def getRole(request):
    """
    Extrae el rol desde el id_token (Auth0 Action que mete el claim). Roles esperados: "Admin", "Externo"
    """
    try:     
        id_token = request.session.get("id_token_payload") or {}
        namespace = settings.AUTH0_NAMESPACE
        role = id_token.get(f"{namespace}/role")
        if not role and hasattr(request.user, "social_auth"):
            for sa in request.user.social_auth.all():
                extra = sa.extra_data or {}
                role = (extra.get("id_token_payload") or {}).get(f"{namespace}/role")
                if role:
                    break
        return role
    except Exception:
        return None