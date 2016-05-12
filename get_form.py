#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: rookie
import re
import sys
import json
import base64
import random
import requests
import urlparse
from bs4 import BeautifulSoup

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
    "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
    "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
    "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
]

def random_useragent():
    return random.choice(USER_AGENTS)
'''
设置一个随机IP，去掉10 172 192这种内网的ip地址
这样会产生一个问题，如果生成的IP是国外的，则会产生无法访问的可能
最好的办法就是根据当前的域名解析了生成IP来进行判断
'''
def random_x_forwarded_for():
    numbers = []
    while not numbers or numbers[0] in (10, 172, 192):
        numbers = random.sample(xrange(1, 255), 4)
    return '.'.join(str(_) for _ in numbers)

def auto_fill_form(name):
    """
    自动填写表单
    """
    ret_val = ""
    form_dict = {
        'name': 'aSdFh1',
        'usr': 'aSdFh1',
        'author': 'aSdFh1',
        'user': 'aSdFh1',
        'username': 'aSdFh1',
        'uid': '8888',
        'num': '123456',
        'nick': 'aSdFh1',
        'addr': '3137 Laguna Street',
        'address': '3137 Laguna Street',
        'area': '555',
        'age': '20',
        'day': '17',
        'month': '7',
        'year': '1986',
        'eta': '20',
        'data': '01/01/1967',
        'date': '01/01/1967',
        'birth': '01/01/1967',
        'birthday': '01/01/1967',
        'city': 'Beijing',
        'state': 'Beijing',
        'ville': 'Beijing',
        'province': 'Beijing',
        'region': 'Taiwan',
        'country': 'China',
        'comp': 'aSdFh1',
        'company': 'aSdFh1',
        'entreprise': 'aSdFh1',
        'cc': '4111111111111111',
        'creditcard': '4111111111111111',
        'cardnum': '4111111111111111',
        'credit': '4111111111111111',
        'mail': 'sample@email.tst',
        'e-mail': 'sample@email.tst',
        'email': 'sample@email.tst',
        'sender': 'sample@email.tst',
        'employer': 'aSdFh1',
        'exp': '11/2011',
        'expiration': '11/2011',
        'fax': '317-317-3137',
        'genere': 'male',
        'gender': 'male',
        'sex': 'male',
        'pwd': 'aSdFh1',
        'pwd2': 'aSdFh1',
        'pass': 'aSdFh1',
        'pass2': 'aSdFh1',
        'userpassword': 'g00dPa$$w0rD',
        'userpassword2': 'g00dPa$$w0rD',
        'password': 'g00dPa$$w0rD',
        'password2': 'g00dPa$$w0rD',
        'confirm': 'true',
        'verify': 'true',
        'retype': 'true',
        'tel': '555-666-0606',
        'phone': '555-666-0606',
        'cell': '13412345678',
        'telephone': '13412345678',
        'postal': '100044',
        'zip': '100044',
        'zipcode': '100044',
        'code': '100044',
        'msn': 'sample@email.tst',
        'yahoo': 'sample@email.tst',
        'gtalk': 'sample@email.tst',
        'qq': '100086',
        'web': 'http://www.test.com',
        'site': 'http://www.test.com',
        'website': 'http://www.test.com',
        'langue': 'english',
        'language': 'english'
    }
    name = name.lower()
    if name in form_dict:
        ret_val = form_dict[name]
    return ret_val

def getform(url):
    '''
    匹配页面内含有的form action 以及对应的值
    '''
    result = []
    vul_results = []
    if "://" not in url:
        url = 'http://%s' % url.rstrip('/')
    url = url.rstrip('/')
    headers = {
        "User-Agent": random_useragent(),
        "X_FORWARDED_FOR": random_x_forwarded_for(),
        "Referer" : url
    }
    try:
        response = requests.get(url,headers=headers,timeout=15,verify=False, allow_redirects=False)
    except Exception, e:
        print str(e)
        return
    if response.status_code == 200:
        soup = BeautifulSoup(response.text)
        #获取页面form
        if not soup.find_all('form'):
            vul_results.append(({"url": url,
            "probe": {"payload": "",
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    }}))
        for form_laber in soup.find_all('form'):
            #print form_laber
            #h获取页面action
            if not form_laber.get('action'):
                acturl = url
            else:
                #如果含有://即使包含了http://与https://这类地址
                if '://' in form_laber.get('action'):
                    acturl = form_laber.get('action')
                else:
                    #如果不包含,开始分去类别
                    scheme, netloc, path, params, query, _ = urlparse.urlparse(url)
                    if form_laber.get('action').startswith('/'):
                        acturl = scheme+'://'+netloc+form_laber.get('action')
                        # action不是以'/'开头(即从当前目录开始)
                    else:
                        # 如果以文件名结尾
                        if path[path.rfind('/') + 1:].strip() == '' or path[path.rfind('/') + 1:].find('.') != -1:
                            path = path[:path.rfind('/')]
                        if path.startswith('/'):
                            path = path[1:]
                        if path == '':
                            acturl = scheme+'://'+netloc+'/'+form_laber.get('action')
                        else:
                            acturl = scheme+'://'+netloc+'/'+path+'/'+form_laber.get('action')
            #获取页面input
            laber_list = form_laber.find_all('input')
            #laber_list = form_laber.find_all('input') + form_laber.find_all('button')
            data = ''
            if not laber_list:
                return
            for laber in laber_list:
                #首先匹配button或者submit提交的参数
                if str(laber.get('name')).find('button')==-1 or str(laber.get('name')).find('submit')==-1:
                    #如果类型为复选框
                    if str(laber.get('type')).find('checkbox')!=-1 and str(laber.get('name')).find('selectdb')!=-1:
                        if laber.get('id') and laber.get('value'):
                            value = laber.get('value')
                        elif laber.get('id'):
                            value = laber.get('id')
                        elif laber.get('value'):
                            value = laber.get('value')
                    #如果类型为隐藏
                    if str(laber.get('type')).find('hidden')!=-1:
                        if laber.get('id') and laber.get('value'):
                            value = laber.get('value')
                        if laber.get('value'):
                            value = laber.get('value')
                        elif laber.get('id'):
                            value = laber.get('id')
                    else:
                        value = 'casterjs'
                    if len(auto_fill_form(str(laber.get('name'))))>0:
                        value = auto_fill_form(str(laber.get('name')))
                        data = data + laber.get('name')+'='+value+'&'
                    else:
                        if laber.get('name') is not None and laber.get('type') is not None:
                            data = data + laber.get('name')+'='+value+'&'
            #如果.net的仅仅就是__VIEWSTATE=xxx考虑去掉，自动切换为get
            if data.rstrip('&').find('&') == -1 and data.rstrip('&').find('__VIEW')!=-1:
                data = ''
            #获取页面method
            if not form_laber.get('method'):
                actmethod = 'GET'
            elif str(form_laber.get('method')).find('get')!=-1:
                actmethod = 'GET'
            elif str(form_laber.get('method')).find('post')!=-1:
                actmethod = 'POST'
            else:
                actmethod = form_laber.get('method')
            #print actmethod
            #如果匹配到提交方式为get
            if str(actmethod).find('get')!=-1 or str(actmethod).find('GET')!=-1:
                acturl = acturl +'?'+data.rstrip('&')
            if len(data.rstrip('&')) == 0:
                actmethod = 'GET'

            vul_results.append(({"url": url,
                "probe": {
                    "payload": data.rstrip('&'),
                    "method": actmethod,
                    "url": acturl,
                    "headers": headers,}}))
    #return (json.dumps(vul_results, indent=4))
    return vul_results


if __name__ == "__main__":
   if len(sys.argv) == 2:
      result = getform(sys.argv[1])
      for lists in result:
          data = base64.b64encode(json.dumps(lists["probe"]))
          #url = lists["url"]
          url = lists["probe"]["url"]
          print url+' '+data
      sys.exit(0)
   else:
       print ("usage: %s url" % sys.argv[0])
       sys.exit(-1)
