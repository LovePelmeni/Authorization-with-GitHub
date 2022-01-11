from django.contrib import admin

# Register your models here.
from django.contrib.admin import ModelAdmin

from .models import CustomUser


class CustomUserAdmin(ModelAdmin):
     model = CustomUser

     list_display = ['username', 'email', 'password', 'is_blocked', 'is_superuser', 'is_admin']
     fields = ['username', 'email', 'password', 'is_blocked', 'is_superuser', 'is_admin']

admin.site.register(CustomUser, CustomUserAdmin)

