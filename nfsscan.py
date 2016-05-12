#-*- coding: utf-8 -*-
#python2.7.x  ip_scaner.py
 
'''
由于内网经常开启nfs服务，检测NSF是否开启
并且检测NFS共享的目录并列出来
'''

import socket
import sys
import os
import time
import thread
 
def scan(ip_str):
    '''
    检测扫描端口是否开启
    如果有开启，尝试使用showmount -e去检测
    '''
    port = '2049'
    cs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    address=(str(ip_str),int(port))
    status = cs.connect_ex((address))
    #若返回的结果为0表示端口开启
    if(status == 0):
        print "%s may have nfs service" %(ip_str)
        cmd = ["showmount", "-e",ip_str]
        output = os.popen(" ".join(cmd)).readlines()
        print output
    cs.close()
	
def find_ip(ip_prefix):
    '''
    给出当前的192.168.1 ，然后扫描整个段所有地址
    '''
    for i in range(1,256):
        ip = '%s.%s'%(ip_prefix,i)
        thread.start_new_thread(scan, (ip,))
        time.sleep(0.5)
     
if __name__ == "__main__":
    commandargs = sys.argv[1:]
    args = "".join(commandargs)
    #getip = socket.gethostbyname(socket.gethostname())
    #ip_prefix = '.'.join(getip.split('.')[:-1])   
   
    ip_prefix = '.'.join(args.split('.')[:-1])
    find_ip(ip_prefix)