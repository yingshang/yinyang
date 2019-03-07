from django.contrib.auth.hashers import make_password

from apps.models import User

def create():
    password = make_password('123456', None, 'pbkdf2_sha256')
    for i in range(1,4):
        for j in range(1,60):
            User.objects.get_or_create(username='111'+str(i)+str(j).zfill(2),password=password,class_group="1"+str(i))
