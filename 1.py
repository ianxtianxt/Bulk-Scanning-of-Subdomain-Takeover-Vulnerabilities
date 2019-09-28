#!/usr/bin/env python
# _*_ coding: utf-8 _*_



import sys
version = sys.version_info
if version < (3, 0):
    print('The current version is not supported, you need to use python3')
    sys.exit()

import dns.resolver
import tldextract
import requests
import datetime
from threading import Semaphore
import threading

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
nowTime=str(nowTime).replace(' ','-').replace(':','-')

sem=Semaphore(500)#线程数
sudbdomain='domain_url.txt' #整理好的子域名文件


def filewrite(text,lock):#log记录实时写入文件。
    lock.acquire()
    outfile=open('Result-' + nowTime + '.txt', 'a', encoding='utf-8')
    outfile.write(text+'\n')
    outfile.close()
    lock.release()

def cname_query(subdomain,sem,lock):#查询cname地址
    try:
        subdomain=subdomain.replace('http://','').replace('https://','').replace('/','')
        cname = dns.resolver.query(subdomain, 'CNAME')
        for i in cname.response.answer:
            for j in i.items:
                res = tldextract.extract(j.to_text())#提取cname的主域名
                domain=res.domain + '.' + res.suffix
                regurl = 'https://checkapi.aliyun.com/check/checkdomain?domain={}&command=&token=Y3d83b57bc8aca0f156381976a6171f4a&ua=&currency=&site=&bid=&_csrf_token=&callback=jsonp_1569557125267_14652'.format(
                    domain)
                try:
                    res2 = requests.get(regurl, timeout=5, verify=False)#查询cname指向的域是否可注册
                    if 'avail":1' in str(res2.content):
                        print(subdomain+' ***存在子域名接管漏洞，接管地址：'+domain)
                        filewrite(subdomain+' ***存在子域名接管漏洞，接管地址：'+domain,lock)#记录实时写入文件
                    else:
                        print(subdomain+' 失败')
                        filewrite(subdomain+' 失败',lock)#记录实时写入文件

                except Exception as e:
                    print(e)

    except Exception as e:
        print(subdomain + ' 不存在cname')
        filewrite(subdomain + ' 不存在cname', lock)#记录实时写入文件
        print(e)
    finally:
        sem.release()





file=open(sudbdomain,'r',encoding='utf-8').read().split('\n')
lock=threading.Lock()

for i in file:
    sem.acquire()
    threading.Thread(target=cname_query,args=(i,sem,lock,)).start()
