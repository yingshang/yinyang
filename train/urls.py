"""train URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path,re_path
from apps.views import *
from django.conf import settings
from django.views import static


urlpatterns = [

        path('',base),
        path('account/login',login_view),
        path('account/logout',logout_view),
        path('index',index),
        path('pull',pull),
        re_path(r"^vul/(?P<type>(.+))/$", image),
        path('api/images',image_api),
        path('api/test',test_api),
        path('test/',test),
        path('start',start),
        path('stop',stop),
        path('key',key),
        path('ranking',ranking),
        path('api/rank',rank_api),
        re_path(r'^vul/(?P<group>(.+))/course',course),
        path('admin/', admin.site.urls),
]
