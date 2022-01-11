import json
import threading
import urllib.request
from dataclasses import dataclass, field
from json import JSONDecodeError

from PIL import Image
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.contrib.sites.shortcuts import get_current_site
from django.core.files import File
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import models
from django.db.models import Q, F, ExpressionWrapper
from django.db.models.fields.files import ImageFieldFile
from django.http import HttpResponseRedirect, HttpResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404

from django.urls import reverse
from django.views import View

import logging
from mailchimp3 import MailChimp
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error

from .models import CustomUser, ImageStorage
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

logger = logging.getLogger(__name__)
#
# GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
# GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
#
# GOOGLE_RESOURCE_SERVER_URL = 'https://www.googleapis.com/auth/userinfo.profile'

import requests
from oauthlib.oauth2 import WebApplicationClient

GET_TOKEN_URL = 'https://github.com/login/oauth/access_token'
AUTHORIZATION_URL = 'https://github.com/login/oauth/authorize'
RESOURCE_SERVER_URL = 'https://api.github.com/user'

REPOSITORY_URL = 'https://api.github.com/repositories/'

client_id = '7f1d7fc356922ac0a70d'
client_secret = '9f7c198fe580c0b9ab54506841753f027271250f'

failed_codes = [error for error in range(400, 415)]

client = WebApplicationClient(client_id)
auth_code_redirect = 'http://127.0.0.1:8000/get/auth/token/'


@dataclass
class ExtendedViewClass(View):
    template_name: str
    context: dict = field(default_factory={'title': 'WebPage Title', 'banner': 'Web Page'})
    data = {}

    def get_default_data(self, request, **kwargs):
        self.data.update({'users': CustomUser.objects.exclude(username=request.user.username)})
        return {**self.data, **kwargs}

    def process_get(self, request, **kwargs):
        bar_context = self.get_default_data(request, **kwargs)
        return render(request, self.template_name, context={**bar_context, **self.context})

def get_full_page_url(request, url_name, kwargs=None):
    from django.contrib.sites.shortcuts import get_current_site
    domain = get_current_site(request).domain
    url = 'http://' + str(domain) + reverse('mailing:' + str(url_name), kwargs=kwargs)
    return url

class MainPage(ExtendedViewClass):

    def __init__(self, **kwargs):
        super(ExtendedViewClass, self).__init__(**kwargs)

        self.template_name = 'mailing/index.html'
        self.context = {'title': 'Main Page', 'banner': 'Main Page'}

    def get(self, request, **kwargs):
        return self.process_get(request, **kwargs)

def process_auth_image_url(user, data):
    """This one is actually processing github user image, to apply it to system object"""
    try:
        import BytesIO
    except ImportError:
        from io import BytesIO
    #sending request with url, which gets from

    id = data.get('id')
    response = requests.get(data.get('avatar_url'), timeout=20)

    user.avatar = InMemoryUploadedFile(file=BytesIO(response.content),
    content_type=response.headers.get('Content-Type'),
    name='image_' + str(id) + '.' + str(response.headers['Content-Type'].split('/')[1]), field_name='avatar',

    charset='utf-8', size=len(response.headers['Content-length']))

    user.save()

def authorize_user(request, response):
    auth_data = {}
    usernames_list = CustomUser.objects.values_list('username', flat=True).distinct()
    try:
        #updating data to dict python format...
        decoded_data = json.loads(response.text)
        auth_data.update({'username': decoded_data.get('login'), 'email': decoded_data.get('email')})

        #Checking for user existence in database, otherwise authenticating him with request data
        if auth_data['username'] not in usernames_list:
            user = CustomUser.objects.create_user(**auth_data)
            logger.debug('user has been created')
            #add_user_to_mailing(request, {"username": user.username})

        else:
            user = authenticate(request, **auth_data, google_confirmed=True)

        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        logger.info('User has confirmed his github credentials')

        process_auth_image_url(user, data=decoded_data)

        return redirect(get_full_page_url(request, url_name='get_profile', kwargs={"username": user.username}))

    except JSONDecodeError as json_err:
        logger.error(msg=json_err.msg)
        #Except there is some problems with decode adding new error message to logger var.

    return redirect(request.META.get('HTTP_REFERER'))

def get_user_profile_data(request, token):
    logger.info('token has been received...')

    headers = {'Authorization': '%s %s' % (token['token_type'].capitalize(), token['access_token'])}
    user_data_response = requests.get(RESOURCE_SERVER_URL, headers=headers, timeout=20)

    return authorize_user(request, response=user_data_response)

def send_github_auth_request(request):
        return redirect(client.prepare_request_uri(uri=AUTHORIZATION_URL, redirect_uri=auth_code_redirect,
            scope=['read:user'], state='D8VAo311AAl_49AtdNM51HA'
        ))

def send_token_request(request, url, data):

    response = requests.post(url, data=data, timeout=20)
    client.parse_request_body_response(response.text)

    if client.token and response.status_code not in failed_codes:

        timer = threading.Timer(client.token.get('expires_in'), send_github_auth_request,
        kwargs={"request": request})

        timer.start()
        logger.debug('Threading started.... waiting for token expiration')

        return get_user_profile_data(request, token=client.token)

def get_access_token(request):
    try:
        data = client.prepare_request_body(

            code=request.GET.get('code'),
            client_id=client_id,
            client_secret=client_secret
        )

        return send_token_request(request, url=GET_TOKEN_URL, data=data)

    except CustomOAuth2Error:
        return send_github_auth_request(request)

def get_user_profile(request, **kwargs):
    template_name = 'mailing/profile.html'
    username = kwargs.get('username')

    user = get_object_or_404(CustomUser, username=username)

    if user is not None:
        logger.debug('%s has got his profile' % user.username)
        return render(request, template_name, context={'user': user,

    'banner': 'Hello, %s!' % user.username, 'title': 'Profile', 'count_followers': count_followers(request, username=username)})

def get_user_followers_list(request, username):
    us_list = []
    user = get_object_or_404(CustomUser, username__iexact=username)

    response = requests.get('https://api.github.com/users/%s/followers' % user.username, timeout=20)
    if response and response.status_code not in failed_codes:

        dec_data = response.json()
        for key, value in dec_data:
           if key == 'login':
              us_list.append(dec_data[key].lower())

        return us_list

def is_user_follower(request, username):

    if not request.user.is_authenticated:
        return redirect('mailing:home')

    followers_list = get_user_followers_list(request, username)
    users = CustomUser.objects.annotate(is_friend=models.Value(True if F('username') in followers_list else False))
    print(type(users))
    print(users)

    return users

def count_followers(request, username):
    return len([elem for elem in is_user_follower(request, username) if elem.is_friend])




