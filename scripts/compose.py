import os
import subprocess
import re
#path = input("请输入路径:")

path  = "/tmp/docker"

f = open('/opt/1.txt','w+')
for root, dirs, files in os.walk(path, topdown=False):
    if "cve" in root or "CVE" in root:
        if 'docker-compose.yml' in files and 'Dockerfile' in files:
            f.write("have dockerfile:"+root+'\n')
        elif 'docker-compose.yml' in files and 'Dockerfile' not in files:
            p = os.path.join(root, 'docker-compose.yml')
            f1 = open(p)
            content = f1.read()
            r = re.findall("image:(.*)",content)[0].strip()
            r1 = re.findall('"\d+"',content)
            ports = ""
            for i in r1:
                ports = ports + '- '+i+'\n'
            c = '''
version: "2.0"
services:
  app:
    image: sectrain/%s
    ports:
         %s
            '''%(r,ports)
            print(c)
        else:
            pass
    else:
        f.write("not CVE: "+root + '\n')
