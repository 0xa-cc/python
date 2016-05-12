# python
解释下输入的命令:

1)touch README.md文件是关于工程代码的介绍，类似与使用说明书

2)git init  初始化一个本地的 git仓库，生成隐藏的.git目录(隐藏的.git目录可使用ls -aF命令可以查看到)

3)git add  README.md  把README.md文件添加到仓库中

4)git commit -m "first commit"  执行提交说明，在Gitz中这个属于强制性的

5)git remote add origin https://github.com/XFZLDXF/TEST.git   添加本地仓库origin和指定远程仓库地址

6)git push origin master  推送本地仓库到远程指定的master分支上

python-code

自己常用的一些脚本

get_form.py 一个获取页面form信息并填充的脚本

portscan.py 扫描全端口的脚本

nfsscan.py  探测NFS服务

rsync.py 探测rsync服务

scanc.py 探测某个网站是否在某个范围内

weblogic_ssrf.py WEBLOGIC SSRF扫描内网端口
