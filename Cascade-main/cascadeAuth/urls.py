# The URL addresses the pops up when the user interacts with the website.

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.homepage, name='homepage'),

    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),

    path('captcha/', views.captcha, name='captcha'),
    path('otp/', views.otp, name='otp'),
    path('resend-otp/', views.resend_otp, name='resend_otp'), 
    path('security-questions-auth/', views.security_questions_auth, name='security_questions_auth'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('security-questions/', views.security_questions, name='security_questions'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('confirmation/', views.confirmation, name='confirmation'),
    path('activation_success/', views.activation_success, name='activation_success'),
    path('activation_invalid/', views.activation_invalid, name='activation_invalid'),
    
    
    path('password-reset/', views.password_reset, name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='cascadeAuth/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.resetPassword, name='resetPassword'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='cascadeAuth/password_reset_complete.html'), name='password_reset_complete'),
    
    path('logout/', views.logout, name='logout'),
]