from django.contrib.auth import login
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import ObjectDoesNotExist

from .models import CustomUser


class BaseAuthBackend(BaseBackend):

    def authenticate(self, request, username=None, email=None, google_confirmed=False, **kwargs):
        new_user = CustomUser.objects.get(username=username)
        if google_confirmed and new_user:
            return new_user

        else:
            return None

class BaseAdminAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            user = CustomUser.objects.get(username=username)
            check_password = user.check_password(password)
            if user and check_password and user.is_admin:
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return user

            else:
                return None

        except ObjectDoesNotExist:
            return None