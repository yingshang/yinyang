

````
iptables -A INPUT -p tcp --dport 8000  -j ACCEPT
iptables -A INPUT -p tcp -s IP --dport 8000  -j ACCEPT

iptables-save > /etc/iptables.rules
 vi /etc/network/if-pre-up.d/iptables #创建文件，添加以下内容，使防火墙开机启动
!/bin/bash
iptables-restore < /etc/iptables.rules

# chmod +x /etc/network/if-pre-up.d/iptables #添加执行权限

# iptables -L -n查看规则是否生效.

iptables -L INPUT --line-numbers | awk 'NR> 2 && $8!="" {print $1, $8}'

iptables -D INPUT 1
````