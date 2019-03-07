
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

未对CSRF设防，加关注、取消关注，直接为GET方式，可导致CSRF蠕虫。
先注册两个账号，一个是攻击者，一个是受害者

攻击者的ID是2，使用攻击者的账号发送下面的链接

```
http://192.168.1.170:7777/index.php?app=public&mod=Follow&act=doFollow&fid=2
```

![image]({path}/5.png)

![image]({path}/6.png)



使用受害者账号登录

点击攻击者发送的链接

![image]({path}/7.png)

![image]({path}/8.png)

![image]({path}/9.png)

