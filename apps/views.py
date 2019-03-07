from django.shortcuts import render
from django.http import JsonResponse,HttpResponseRedirect,HttpResponse
from .models import images,logs,User,ceshi
import random,string
import psutil
from .docker import *
from django.contrib.auth.decorators import login_required
# Create your views here.
import time,json
from django.db.models import Count
from django.contrib.auth import authenticate, login,logout
from django.views.decorators.csrf import csrf_exempt


DOCKER_API_URL = "http://127.0.0.1:5555"

def login_view(request):
    if request.method =='POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect('/')
        else:
            msg = "用户或密码错误!!!"
            return render(request,'login.html',locals())
    else:
        return  render(request,'login.html',locals())


@login_required()
def logout_view(request):
    logout(request)
    return HttpResponseRedirect('/')


@login_required
def base(request):
    return render(request,"base.html",locals())
@login_required
def index(request):
    username = str(request.user)
    date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    image_count = images.objects.all().count()
    memory = psutil.virtual_memory().percent
    #r = requests.get(DOCKER_API_URL + "/containers/json").json()
    id = User.objects.get(username=username).id
    datas = []
    objs = logs.objects.filter(username_id=id).order_by('-time')[0:10]
    for obj in objs:
        datas.append({'id':obj.container,'operation':obj.operation,'time':obj.time})

    return render(request, "index.html", locals())

@login_required
def image(request,type):
    return render(request,"images.html",locals())
@login_required
def start(request):
    img = request.GET.get('img')
    if img == "null":
        return JsonResponse({"code": 0, "msg": "没有镜像，启动不了"})
    group = images.objects.filter(image=img)[0].group
    r = requests.get(DOCKER_API_URL+"/images/"+img+"/json").json()
    name = str(request.user) + '_' +img[0:6]+'_'+ ''.join(random.sample(string.ascii_letters + string.digits, 10))
    ip = request.META['REMOTE_ADDR']
    try:
        port = ''

        for i in r['Config']['ExposedPorts']:
            port = '-p '+i+'  '+port
        CMD = "docker run -d "+port+" --name "+name+"  "+img
        testcmd = "docker run -d  -v /tmp/"+str(request.user) + '_' +img+":/tmp   "+port+" --name "+name+"  "+img
        status = judge_status(request,img)
        if status ==1:
            if group == "normal":
                try:
                    print(ceshi.objects.get(image = img).status)
                    if ceshi.objects.get(image = img).status == 1:
                        subprocess.check_call(testcmd, shell=True)
                    else:
                        return JsonResponse({"code": 0, "msg": "课程已经锁定，请联系管理员开启课程!"})
                except  Exception as e:
                    print(repr(e))
                    return JsonResponse({"code": 0, "msg": "镜像异常"})
            else:
                subprocess.check_call(CMD, shell=True)
            r1 = requests.get(DOCKER_API_URL + "/containers/json").json()
            for k in r1:
                if str(request.user) + "_" in k['Names'][0]:
                    contain_ip = k['NetworkSettings']['Networks']['bridge']['IPAddress']

                    cmd1 = ''' iptables -L DOCKER --line-numbers | awk -v OFS=',' ' $6=="%s" && NR>2  {print $1 } ' ''' % contain_ip
                    t = subprocess.check_output(cmd1, shell=True)
                    data = []
                    for i in t.decode('utf8').split('\n'):
                        if len(i) !=0:
                            data.append(int(i))
                    for i in sorted(data,reverse=True):
                        cmd3 = "iptables -D DOCKER " + str(i)
                        subprocess.check_call(cmd3, shell=True)

                    for n in k['Ports']:
                        cmd2 = "iptables -I DOCKER -p tcp -s " + ip + " -d " + contain_ip + " --dport " + str(
                            n['PrivatePort']) + " -j ACCEPT"
                        subprocess.check_call(cmd2, shell=True)
            id = User.objects.get(username=str(request.user)).id
            logs.objects.create(username_id=id,container=img,operation="打开镜像")

            return JsonResponse({"code": 1, "msg": "镜像启动!!!!"})
        elif status ==2:
            return JsonResponse({"code": 2, "msg": "只能开启一个镜像,请先停止镜像!!!"})
        elif status ==3:
            return JsonResponse({"code": 3, "msg": "内存已经满了，请联系管理员!!!"})

        else:
            return JsonResponse({"code": 0, "msg": "镜像已经启动，请勿多开"})

    except  Exception as e:
        return JsonResponse({"code":0,"msg":"镜像异常"})

@login_required
def stop(request):
    img = request.GET.get("img")
    r = requests.get(DOCKER_API_URL + "/containers/json").json()
    contain = ''

    for i in r:
        if i['Image'][0:10] in img and str(request.user) in i['Names'][0]:
            contain = i['Id'][0:10]
    if len(contain) ==0:
        return JsonResponse({"code":0,"msg":"容器异常!!!!"})
    else:
        r1 = requests.post(url=DOCKER_API_URL+'/containers/'+contain+'/stop')

        for k in r:
            if str(request.user) + "_" +img[0:6] in k['Names'][0]:
                contain_ip = k['NetworkSettings']['Networks']['bridge']['IPAddress']
                cmd = '''  iptables -L DOCKER --line-numbers | awk 'NR> 2  && $6=="%s" {print $1}' '''%contain_ip
                t = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
                data = []
                for i in t.decode('utf8').split('\n'):
                    if len(i) !=0:
                        data.append(int(i))
                for i in sorted(data,reverse=True):
                    subprocess.check_call("iptables -w -D DOCKER "+str(i),shell=True)
        id = User.objects.get(username=str(request.user)).id
        logs.objects.create(username_id=id, container=img, operation="关闭镜像")
        return JsonResponse({"code":1,"msg":"容器停止!!!"})

@login_required
def image_api(request):
    type = request.GET.get("type")
    try:
        page = int(request.GET.get("page")) or 1
    except:
        page = 1
    try:
        limit = int(request.GET.get("limit")) or 10
    except:
        limit = 10
    start = (page - 1) * limit
    end = page * limit

    results = images.objects.filter(group=type)[start:end].values("id", "name", "token","image","weather_img")
    count = images.objects.filter(group=type).count()

    data = containers(request,results)
    return JsonResponse({"code": 0, "msg": "", "count": count, "data": data}, safe=False)

@login_required
def course(request,group):
    token = request.GET.get("token")
    name = images.objects.get(token=token).name
    text = md(name,group)
    return render(request,"course.html",locals())

@login_required
def pull(request):
    if request.user.is_superuser:
        pull_image()
        return JsonResponse({"code": 1, "msg": "拖取镜像成功"})
    else:
        return JsonResponse({"code":0,"msg":"please contact manager!!"})




@login_required
def test_api(request):
    type = request.GET.get('type')
    try:
        page = int(request.GET.get("page")) or 1
    except:
        page = 1
    try:
        limit = int(request.GET.get("limit")) or 10
    except:
        limit = 10
    start = (page - 1) * limit
    end = page * limit

    data = []

    if type == "normal":
        objs = ceshi.objects.filter(type="normal")[start:end].values("id", "course_name", "desc","image","score")
        count = ceshi.objects.filter(type="normal").count()
        data = containers(request,objs)
        return JsonResponse({"code": 0, "msg": "", "count": count, "data": data}, safe=False)
    elif type == "end":
        pass
    else:
        pass

def test(request):
    type = request.GET.get('type')
    return render(request,"test.html",locals())

@csrf_exempt
@login_required
def key(request):
    image = request.GET.get('image')
    if request.method == 'POST':
        key = request.POST.get('key')
        path = '/tmp/'+str(request.user)+'_'+image+'/key.txt'
        f = open(path)
        t = f.readline()
        f.close()
        if t == key:
            course_id = ceshi.objects.get(image=image).id
            user_id = User.objects.get(username=str(request.user)).id
            score = ceshi.objects.get(image=image).score
            achievement.objects.get_or_create(course_id=course_id,user_id=user_id,score=score,image=image,result="完成测试")
            return JsonResponse({"code":1,"msg":"恭喜你！！！成功完成测试"})

        else:
            return JsonResponse({"code": 0, "msg": "key值不对，请再尝试"})

    else:
        try:
            desc = ceshi.objects.get(image=image).desc
            return render(request,'key.html',locals())
        except:
            return HttpResponse("异常行为")


def ranking(request):
    role = User.objects.get(username=str(request.user)).role
    return render(request,'rank.html',locals())


def rank_api(request):
    data = []
    group = User.objects.get(username=str(request.user)).class_group
    role = User.objects.get(username=str(request.user)).role

    if role == 1: #teacher
        group = group.split(',')

        return JsonResponse({"code": 0, "msg": "", "count": 0, "data": data})
    elif role == 0 :
        if group == None:
            return JsonResponse({"code": 0, "msg": "", "count": 0, "data": data})

        else:
            stus = User.objects.filter(class_group=group)
            count = stus.count()
            for stu in stus:
                id = stu.id
                i = []
                username = stu.username
                score = 0
                objs = achievement.objects.filter(user_id=id)
                for obj in objs:
                    score = score + obj.score
                try:
                    time = objs.order_by('-time')[0].time
                except IndexError:
                    time = ""

                data.append({'username':username,'score':score,'time':time})
        return JsonResponse({"code": 0, "msg": "", "count": count, "data": data})
    else:
        pass