import requests
import subprocess
url = "http://127.0.0.1:5555/images/json"
r = requests.get(url).json()

for i in r:
    tags = i['RepoTags']
    for tag in tags:
        cmd = "docker save "+tag+" -o  "+tag+".tar.gz"
        print(cmd)
        try:
            subprocess.check_call(cmd,shell=True)
        except subprocess.CalledProcessError:
            pass
