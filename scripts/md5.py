import hashlib
import os
import re
import random
import uuid
path = "F:\\train\\static\\courses"

for root, dirs, files in os.walk(path, topdown=False):
    for name in files:
        if "course.md" in name:
            course = os.path.join(root, name)
            f = open(course,'r',encoding='UTF-8')
            f1 = open(os.path.join(root, "Dru9R1WK9HnlgV67i098L2nc4KKdgU8H.md"),'w+',encoding='UTF-8')
            content = f.read()
            lists = re.findall(".*?(\d+).png",content)
            for  i in lists:
                picture = os.path.join(root, i+'.png')
                uid = str(uuid.uuid4())
                #print("![image]({path}/"+i+".png)")
                #print("![image]({path}/"+uid+".png)")
                content = content.replace("![image]({path}/"+i+".png)","![image]({path}/"+uid+".png)")
                try:
                    os.rename(picture,os.path.join(root,uid+'.png'))
                except FileNotFoundError:
                    print(os.path.join(root,i+".png"))
            f1.write(content)
