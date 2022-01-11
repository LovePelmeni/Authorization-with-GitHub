import random
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.db import models

class CustomManager(BaseUserManager):

    def create_user(self, username, email=None, **kwargs):
        default_params = {'is_blocked': False, 'is_superuser': True, 'is_admin': False}
        default_params.update(**kwargs)

        if not username:
            raise ValueError('empty username')

        user = self.model(username=username, email=email, **default_params)
        user.save(using=self._db)

        return user

    def create_superuser(self, username, password, email=None):
        if not username:
            raise ValueError('empty username')

        if not password:
            raise ValueError('empty password')

        user = self.model(username=username, email=email, password=password)
        user.set_password(password)

        user.is_admin = True
        user.is_blocked = False
        user.is_superuser = True

        user.save(using=self._db)

        return user

ImageStorage = FileSystemStorage()

class CustomUser(AbstractBaseUser, PermissionsMixin):
    objects = CustomManager()

    @staticmethod
    def get_default_avatar_url():
        return settings.MEDIA_ROOT + '/default_mailing_avatar.png'

    avatar = models.ImageField(verbose_name='Avatar', blank=True, storage=ImageStorage,
    default=settings.MEDIA_ROOT + '/default_mailing_avatar.png', max_length=10000)

    username = models.CharField(verbose_name='Username', unique=True, max_length=50, null=False, blank=False)
    password = models.CharField(verbose_name='Password', max_length=20, blank=True, null=True)

    email = models.CharField(verbose_name='Email', null=True, blank=True,
    max_length=50)
    is_blocked = models.BooleanField(verbose_name='Is Blocked', default=False)

    is_superuser = models.BooleanField(verbose_name='Is Superuser', default=True)
    is_admin = models.BooleanField(verbose_name='Is Admin', default=False)

    USERNAME_FIELD = 'username'

    def __str__(self):
        return self.username

    def get_image_url(self):
        if self.avatar and hasattr(self.avatar, 'url'):
            return self.avatar.url
        else:
            return self.get_default_avatar_url()


