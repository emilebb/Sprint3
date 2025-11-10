from django.db import models
from django.contrib.auth import get_user_model
# Create your models here.
class Client(models.Model):
    name = models.CharField(max_length=120)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=32)
    address = models.TextField(blank=True)
    document_id = models.CharField(max_length=64, unique=True)  # sensible

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} <{self.email}>"

class SecurityEvent(models.Model):
    """Registra intentos de acceso y su resultado (permitido/denegado)."""
    user = models.ForeignKey(get_user_model(), null=True, blank=True,
                             on_delete=models.SET_NULL)
    role = models.CharField(max_length=64, blank=True, default="")
    path = models.CharField(max_length=512)
    method = models.CharField(max_length=16)
    ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.CharField(max_length=64)      
    allowed = models.BooleanField(default=False)
    detail = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["created_at", "allowed", "action"])]