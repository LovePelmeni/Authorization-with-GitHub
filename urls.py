from django.urls import path

from . import views

app_name = 'mailing'
l = 'http://127.0.0.1:8000/get/auth/token/'
k = 'get/auth/token/'

urlpatterns = [

    path('', views.MainPage.as_view(), name='home'),
    path('get/auth/token/', views.get_access_token, name='get_access_token'),
    path('send/github/form/', views.send_github_auth_request, name='send_auth_request'),
    path('send/token/request/<url>/<data?/', views.send_token_request, name='send_token_request'),
    path('user-profile/<str:username>/', views.get_user_profile, name='get_profile'),

]
