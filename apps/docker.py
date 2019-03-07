import requests
import os
import subprocess
from .models import images,User
import psutil
from celery.decorators import task
from .models import achievement
import string
import random

DOCKER_API_URL = "http://127.0.0.1:5555"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKER_DIR = BASE_DIR+'/docker/'


@task
def pull_image():
    images.objects.all().delete()
    for root, dirs, files in os.walk(DOCKER_DIR, topdown=True):
        for name in dirs:
            if os.path.join(root, name).split("/")[-2] == "docker":
                pass
            else:
                images.objects.create(name=os.path.join(root, name).split("/")[-1],group=os.path.join(root, name).split("/")[-2],token=''.join(random.sample(string.ascii_letters + string.digits, 32)))
                try:
                    subprocess.check_call("cd "+os.path.join(root, name)+" && docker-compose create",shell=True)
                    r = requests.get(DOCKER_API_URL + "/images/json").json()
                    for i in r:
                        for j in i['RepoTags']:
                            if os.path.join(root, name).split("/")[-1] in j:
                                obj = images.objects.get(name=os.path.join(root, name).split("/")[-1],group=os.path.join(root, name).split("/")[-2])
                                obj.image = i['Id'].split(":")[-1]
                                obj.weather_img = '有'
                                obj.save()
                except subprocess.CalledProcessError:
                    pass

def judge_status(request,img):
    r1 = requests.get(DOCKER_API_URL + "/containers/json").json()
    n=0
    t = 1
    if len(r1) == 0:
        return 1
    else:
        for i in r1:
            name1 = str(request.user) + '_' + img[0:6] + '_'
            name2 = i['Names'][0]
            if name1 in name2:
                n = n+1
            if str(request.user) in name2:
                t = t+1
        if psutil.virtual_memory().percent >90:
            return 3
        #修改数为打开镜像最大数，默认是1
        elif t>1:
            return 2
        elif n==0:
            return 1
        else:
            return 0


def md(name,group):
    course_path=BASE_DIR+'/static/courses'
    full_path = course_path+'/'+group+'/'+name+'/course.md'
    try:
        f = open(full_path).read()
        text = f.replace("{path}",'/static/courses/'+group+'/'+name)
        return text
    except FileNotFoundError:
        return 0


def containers(request,results):
    data = []
    for i in results:
        r = requests.get(DOCKER_API_URL + "/containers/json").json()
        t = ''
        try:
            user_id = User.objects.get(username=str(request.user)).id
            i['result'] = achievement.objects.get(image=i['image'],user_id=user_id).result
        except:
            i['result'] = "未完成测试"
        for k in r:
            try:
                name = str(request.user) + "_" + str(i['image'][0:6])
            except:
                name = "sagvvvvvvvvvvvvvvvvvvvvvvvdasdasdasdasdasd"

            if name in k['Names'][0]:
                i['status'] = "启动中"
                for n in k['Ports']:
                    t = str(n['PublicPort']) + '->' + str(n['PrivatePort']) + ',' + t
                i['port'] = t
                break
            else:
                i['status'] = "关闭"
        data.append(i)
    return data
