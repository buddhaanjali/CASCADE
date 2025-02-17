from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from cascadeAuth import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('cascadeAuth.urls')),
    path('captcha/', include('captcha.urls')),
]