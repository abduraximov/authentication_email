from django.contrib import admin
from .models import UserConfirmation, CustomUser

@admin.register(CustomUser)
class AdmUser(admin.ModelAdmin):
    ordering = ["-created_at"]
    list_display = ('username', 'id', 'email')

@admin.register(UserConfirmation)
class AdmConf(admin.ModelAdmin):
    list_display = ('user', 'code')


