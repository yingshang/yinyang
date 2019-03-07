import requests
import  subprocess
API_URL = 'http://127.0.0.1:5555/images/json'

r = requests.get(url=API_URL)
images = r.json()

s = "securitytrain"

for i in images:
    for j in i['RepoTags']:
        if s in j:
            subprocess.check_call("docker push "+j,shell=True)
            print(j)
