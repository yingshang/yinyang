import subprocess
import os

for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name == "Dockerfile":
            CMD = "cd "+root+" && docker build -t  securitytrain/"+root.replace("./","").replace("/","")+":sql"+"  ."
            print(CMD)
            subprocess.check_call(CMD,shell=True)
