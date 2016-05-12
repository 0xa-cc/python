#!/usr/bin/env python
# -*- coding:utf-8 -*-
import Queue
import sys
import nmap
import logging
import threading
import time

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s: %(message)s")

class Worker(threading.Thread):  # 处理工作请求
    def __init__(self, workQueue, resultQueue, **kwds):
        threading.Thread.__init__(self, **kwds)
        self.setDaemon(True)
        self.workQueue = workQueue
        self.resultQueue = resultQueue

    def run(self):
        while 1:
            try:
                callable, args, kwds = self.workQueue.get(False)  # get task
                res = callable(*args, **kwds)
                self.resultQueue.put(res)  # put result
            except Queue.Empty:
                break

class WorkManager:  # 线程池管理,创建
    def __init__(self, num_of_workers=10):
        self.workQueue = Queue.Queue()  # 请求队列
        self.resultQueue = Queue.Queue()  # 输出结果的队列
        self.workers = []
        self._recruitThreads(num_of_workers)

    def _recruitThreads(self, num_of_workers):
        for i in range(num_of_workers):
            worker = Worker(self.workQueue, self.resultQueue)  # 创建工作线程
            self.workers.append(worker)  # 加入到线程队列

    def start(self):
        for w in self.workers:
            w.start()

    def wait_for_complete(self):
        while len(self.workers):
            worker = self.workers.pop()  # 从池中取出一个线程处理请求
            worker.join()
            if worker.isAlive() and not self.workQueue.empty():
                self.workers.append(worker)  # 重新加入线程池中
        logging.info('All jobs were complete.')

    def add_job(self, callable, *args, **kwds):
        self.workQueue.put((callable, args, kwds))  # 向工作队列中加入请求

    def get_result(self, *args, **kwds):
        return self.resultQueue.get(*args, **kwds)

def nmapScan(targetHosts,targetport):
    """
    主要用来工作区域
    获取当前的ip地址加入Nmap扫描中
    如果发现地址存活，就输出服务等信息

    -- ----------------------------
    --  Table structure for `result_ports`
    -- ----------------------------
    DROP TABLE IF EXISTS `result_ports`;
    CREATE TABLE `result_ports` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `taskid` varchar(32) COLLATE utf8_bin DEFAULT NULL,
      `address` varchar(256) COLLATE utf8_bin DEFAULT NULL,
      `port` int(11) DEFAULT NULL,
      `service` varchar(256) COLLATE utf8_bin DEFAULT NULL,
      `product` varchar(256) COLLATE utf8_bin DEFAULT NULL,
      `product_version` varchar(256) COLLATE utf8_bin DEFAULT NULL,
      `time` varchar(256) COLLATE utf8_bin DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

    SET FOREIGN_KEY_CHECKS = 1;
    """
    resuls = []
    port_results = []
    try:
        scanner = nmap.PortScanner()
        #-Pn选项 不ping直接扫描,可能会比较慢
        #-n --min-hostgroup 1024 --min-parallelism 1024
        # -sS -P0 -oX - -sV --script=banner --version-light --allports --min-parallelism 100
        #logging.info('nmap -p T:'+str(targetport)+' -sT -sV --script=banner --allports --version-light --min-parallelism 100 '+str(targetHosts))
        scanner.scan(targetHosts,arguments='-p T:'+str(targetport)+' -Pn -sT -sV --script=banner --allports --version-light --min-parallelism 100')
        for targetHost in scanner.all_hosts():
            if scanner[targetHost].state() == 'up' and scanner[targetHost]['tcp']:
                for targetport in scanner[targetHost]['tcp']:
                    if scanner[targetHost]['tcp'][int(targetport)]['state'] == 'open':
                        logging.info(targetHosts+'\t'+str(targetport) + '\t' + scanner[targetHost]['tcp'][int(targetport)]['name'] + '\t' + scanner[targetHost]['tcp'][int(targetport)]['product']+scanner[targetHost]['tcp'][int(targetport)]['version'])
                        resuls.append(({
                                "port": str(targetport),
                                "service": scanner[targetHost]['tcp'][int(targetport)]['name'],
                                "version":scanner[targetHost]['tcp'][int(targetport)]['product']+scanner[targetHost]['tcp'][int(targetport)]['version'],
                                }))
            else:
                break
                continue
            #return resuls
            #logging.DEBUG(json.dumps(port_results, indent=4))
            #return port_results
    except Exception, e:
        #logging.info(targetHosts+'\t'+str(e))
        pass

def is_intranet(ip):
    ret = ip.split('.')
    if not len(ret) == 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '127' and ret[1] == '0':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False

def main():
    ip = str(sys.argv[1])
    if is_intranet(ip):
        sys.exit()
    try:
        num_of_threads = int(sys.argv[2])
    except Exception, e:
        num_of_threads = 10
    _st = time.time()
    wm = WorkManager(num_of_threads)
    ports = [
        '21,23,25,26,37,53,79,81,82,83,84,85,88,89,90,110,111,113,135,139,143,161,199,389,444,445,458,465,514,541,554,587,631,800,801,808,843,873,888,902,903,981,993,995,1010,1011,1025,1026,1027,1028,1030,1031,1032,1034,1046,1080,1081,1111,1311,1443,1720,1723,1755,1801,1863,1935,2000,2001,2002,2004,2005,2006,2008,2010,2013,2049,2100,2103,2105,2107,2121,2222,2500,2525,2601,2604,3000,3030,3128,3306,3333,3372,3690,4000,4440,4443,5000,5061,5080,5200,5222,5666,6000,6001,6002,6003,6004,6005,6006,6007,6009,6082,6100,6666,6699,7000,7001,7002,7004,7007,7070,7100,7200,7443,7777,7999,8000,8001,8002,8008,8009,8010,8011,8021,8022,8031,8042,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8200,8383,8443,8649,8800,8873,8888,8899,9000,9001,9002,9003,9009,9010,9040,9080,9081,9090,9091,9099,9100,9101,9102,9103,9200,9876,9900,9998,9999,10000,10001,10002,10003,10004,10009,15000,20000,30000,48080,49152,49153,49154,49155,49156,49157,49158,49159,58080',
        '22,80,443,3389,53,123,161,111,101',
        '1-20,24,27-36,38-52,54-78,86-87,91-109,112,114-134,136-138,140-142,144-160,162-198,200-388,390-442,446-457,459-464,466-513,515-540,542-553,555-586,588-630,632-799,802-807,809-842,844-872,874-887,889-901,904-980,982-992,994,996-999',
        '1000-1009,1012-1024,1029,1033,1035-1045,1047-1079,1082-1110,1112-1310,1312-1442,1444-1719,1721-1722,1724-1754,1756-1800,1802-1862,1864-1934,1936-1999',
        '2003,2007,2009,2011-2012,2014-2048,2050-2099,2101-2102,2104,2106,2108-2120,2122-2221,2223-2499,2501-2524,2526-2600,2602-2603,2605-2999',
        '3001-3029,3031-3127,3129-3305,3307-3332,3334-3371,3373-3388,3390-3689,3691-3999',
        '4001-4439,4441-4442,4444-4999',
        '5001-5060,5062-5079,5081-5199,5201-5221,5223-5665,5667-5999',
        '6008,6010-6081,6083-6099,6101-6665,6667-6698,6700-6999',
        '7003,7005-7006,7008-7069,7071-7099,7101-7199,7201-7442,7444-7776,7778-7998',
        '8003-8007,8012-8020,8023-8030,8032-8041,8043-8079,8091-8092,8094-8098,8101-8179,8182-8199,8201-8382,8384-8442,8444-8648,8650-8799,8801-8872,8874-8887,8889-8898,8900-8999',
        '9004-9008,9011-9039,9041-9079,9082-9089,9092-9098,9104-9199,9201-9875,9877-9899,9901-9997',
        '10005-10008,10010-14999,15001-19999',
        '20001-29999',
        '30001-39999',
        '40000-48079,48081-49151,49160-49999',
        '50000-58079,58081-59999',
        '60000-65535',
        ]
    for port in ports:
        wm.add_job(nmapScan,str(ip),str(port))
    wm.start()
    wm.wait_for_complete()
    logging.info("job token time "+str(time.time() - _st))

if __name__ == '__main__':
    main()
