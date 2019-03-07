# coding:utf-8
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fortify.settings")
import django
from aduit.models import chandao_info

if django.VERSION >= (1, 7):  # 自动判断版本
    django.setup()


def main():
    f = open('info.txt')
    for line in f:
        ename, header,cname,pid = line.split('	')
        chandao_info.objects.create(ename = ename, header=header,cname=cname,pid=pid)
    f.close()


if __name__ == "__main__":
    main()
    print('Done!')