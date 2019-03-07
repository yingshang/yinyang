from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    class_group = models.CharField(max_length=100,null=True,blank=True)
    role = models.IntegerField(default=0) #stu 0,tea 1
    class Meta(AbstractUser.Meta):
        pass




class images(models.Model):
    name = models.CharField(max_length=100)
    image = models.CharField(max_length=100,null=True)
    group = models.CharField(max_length=100)#tag
    token = models.CharField(max_length=100)
    weather_img = models.CharField(max_length=100,default='没有') #image exist
    create_time = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.name

class logs(models.Model):
    username = models.ForeignKey(User,on_delete=models.CASCADE)
    container = models.CharField(max_length=200)
    operation = models.CharField(max_length=100)
    time = models.DateTimeField(auto_now=True)


class ceshi(models.Model):
    course_name = models.CharField(max_length=100)
    image = models.CharField(max_length=100)
    type = models.CharField(max_length=100)
    desc = models.TextField()
    score = models.IntegerField()
    status = models.IntegerField(default=0) #default close


class achievement(models.Model):
    image = models.CharField(max_length=100)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    course = models.ForeignKey(ceshi,on_delete=models.CASCADE)
    result = models.CharField(max_length=100)
    score = models.IntegerField()
    time = models.DateTimeField()

