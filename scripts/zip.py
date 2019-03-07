import os
import subprocess
path = input(" intput path:")

for root, dirs, files in os.walk(path, topdown=False):
    for name in files:
        if len(root.split('/')) == 4:
            if name.split('.')[-1] == 'zip':
                subprocess.check_call("unzip -o "+os.path.join(root, name)+"  -d "+root,shell=True)
                pass
            elif name.split('.')[-1] == 'rar':

                subprocess.check_call("unrar  x -o+ "+os.path.join(root, name)+" "+root,shell=True)

            else:
                pass


f = open('log',"w+")

for root, dirs, files in os.walk(path, topdown=False):
    for name in files:
        if name == "Dockerfile":
            tag = root.split('/')[3]
            CMD = "cd "+root+" && docker build -t  securitytrain/"+root.split('/')[-1]+":"+tag+"  ."
            print(CMD)
            subprocess.check_call(CMD,shell=True)

f.close()

