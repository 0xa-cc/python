#-*- coding: utf-8 -*-
#python2.7.x  ip_scaner.py
  
'''
检测某个域名是否在某个IP段内
'''
 
import socket
import sys
import os
import time
import thread

host="www.audi.cn"  #需要查找的域名
url="2015css/basic20150413.css"   #网页的特征

def scan(ip_str):
    '''
    检测扫描端口是否开启
    如果有开启，就访问读取源码，并检测url是否在其中
    '''
    port = '80'
    cs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    address=(str(ip_str),int(port))
    status = cs.connect_ex((address))
    #若返回的结果为0表示端口开启
    if(status == 0):
    	#print "ip %s open %s port" %(ip_str,port)
        se=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        se.connect((ip_str,80))
        se.send("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)\r\nHost: %s\r\n\r\n" % host)
        oldbuf = ''
        while True:
            buf = se.recv(1024)
            if not len(buf):
                break
            else:
                buf = oldbuf + buf
                oldbuf = buf
            if buf.find(url)>0:
                print "domain %s maybe on ip:%s\n"% (host,ip_str)
                break       
    cs.close()
     
def find_ip(ip_prefix):
    '''
    给出当前的192.168.1 ，然后扫描整个段所有地址
    '''
    for i in range(1,256):
        ip = '%s.%s'%(ip_prefix,i)
        thread.start_new_thread(scan, (ip,))
        time.sleep(0.1)

      
if __name__ == "__main__":
    commandargs = sys.argv[1:]
    args = "".join(commandargs)    
    
    ip_prefix = '.'.join(args.split('.')[:-1])
    find_ip(ip_prefix)