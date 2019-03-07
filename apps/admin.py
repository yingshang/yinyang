from django.contrib import admin
from .models import *
# Register your models here.


class ceshiadmin(admin.ModelAdmin):
    list_display = ('course_name','status')

