import subprocess
import os

path = input("输入路径:")



for root, dirs, files in os.walk(path, topdown=False):
    for name in files:
        print(os.path.join(root, name))
        subprocess.check_call(" docker load -i "+os.path.join(root, name),shell=True)