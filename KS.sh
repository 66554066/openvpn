#!/bin/bash
# 当你看到这个,恭喜你破解脚本成功
# 希望你用它来多学习，而不是只会改版权
# 本脚本由亿梦解密无修改任何代码除了此处
# 作者 康师傅&掌握核心技术
# 亿梦之家:http://www.ymazz.com
function shellhead() {
	rm -rf $0
	yum install curl -y
	KangLogo='
	==========================================================================
                                                                           
			康师傅免流破解版--WEB流量控制--云免服务器一键搭建--亿梦掌握核心破解				
				Powered by www.ymazz.com 2015-2016					
					All Rights Reserved							
                                                                         
							by 亿梦之家 2016-07-27             
	==========================================================================';
	errorlogo='
	==========================================================================
			康师傅免流WEB流量控制云免服务器亿梦破解版一键搭建     		       
				Powered by www.ymazz.com 2015-2016       		       
						All Rights Reserved                                                                                       
	==========================================================================';
	finishlogo='
	==========================================================================
			康师傅免流WEB流量控制云免服务器亿梦破解版一键搭建      	            
				Powered by www.ymazz.com 2015-2016        		       
						All Rights Reserved               	   			                                                                      
	==========================================================================';
	keyerrorlogo='
	==========================================================================
				康师傅免流亿梦破解版™服务验证失败，安装被终止				
																			
					OpenVPN+Squid+Mproxy+流量控制安装失败    				
					Powered by www.ymazz.com 2015-2016    				   
							All Rights Reserved         					                                                                               
	==========================================================================';
	http="http://"; 
	Vpnfile='centos77';
	sq=squid.conf;
	mp=mproxy-kangml;
	author=author-kangml.tar.gz
	RSA=EasyRSA-2.2.2.tar.gz;
	Host='kangml-10046394.file.myqcloud.com';
	IP=`curl -s http://members.3322.org/dyndns/getip`;
	squser=auth_user;
	mysqlip='null';
	KRSA=easy-rsa.zip;
updatesql='update.sql';
	webfile32='ioncube-32.tar.gz';
	webfile64='ioncube_loaders-64.tar.gz';
	phpmyadminfile='phpMyAdmin-4.0.10.15-all-languages.tar.gz';
	key=`curl -s http://ml.qqzzz.net/ksfpass/`
	upload=transfer.sh;
	jiankongfile=jiankong.zip
	lnmpfile='kang-lnmp.tar.gz';
	webfile='kangml-web.zip';
	uploadfile=kangml-openvpn.tar.gz;
	return 1
}
function authentication() {
echo 
echo -n -e "请输入授权码 [\033[32m $key \033[0m] ："
read PASSWD
readkey=$PASSWD
if [[ ${readkey%%\ *} == $key ]]
    then
        echo 
		echo -e '\033[32m授权成功！\033[0m即将开始搭建...'
		sleep 3
    else
        echo
		echo -e '\033[31m授权失败\033[0m'
		sleep 3
echo "$keyerrorlogo";
exit
fi
return 1
}
function InputIPAddress() {

echo 
echo "正在检测您的IP是否正确加载..."

	if [[ "$IP" == '' ]]; then
		echo '无法检测您的IP';
		read -p '请输入您的公网IP:' IP;
		[[ "$IP" == '' ]] && InputIPAddress;
	fi;
	[[ "$IP" != '' ]] && echo -e '\033[32m[OK]\033[0m 您的IP是:' && echo $IP;	
	sleep 2
	return 1
}
function readytoinstall() {
	echo 
	echo "开始整理安装环境..."
	echo "可能需要1分钟"
	sleep 2

	echo
	echo "整理残留环境中..."
	systemctl stop openvpn@server.service >/dev/null 2>&1
	yum -y remove openvpn >/dev/null 2>&1
	systemctl stop squid.service >/dev/null 2>&1
	yum -y remove squid >/dev/null 2>&1
	killall mproxy-kangml >/dev/null 2>&1
	rm -rf /etc/openvpn/*
	rm -rf /root/*
	rm -rf /home/*
	sleep 2 
	systemctl stop httpd.service >/dev/null 2>&1
	systemctl stop mariadb.service >/dev/null 2>&1
	systemctl stop mysqld.service >/dev/null 2>&1
	/etc/init.d/mysqld stop >/dev/null 2>&1
	yum remove -y httpd >/dev/null 2>&1
	yum remove -y mariadb mariadb-server >/dev/null 2>&1
	yum remove -y mysql mysql-server>/dev/null 2>&1
	rm -rf /var/lib/mysql
	rm -rf /var/lib/mysql/
	rm -rf /usr/lib64/mysql
	rm -rf /etc/my.cnf
	rm -rf /var/log/mysql/
	rm -rf 
	yum remove -y nginx php-fpm >/dev/null 2>&1
	yum remove -y php php-mysql php-gd libjpeg* php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-bcmath php-mhash php-fpm >/dev/null 2>&1
	sleep 2
	echo "整理完毕"
	echo 
	echo 


	echo "正在检查并更新源..."
	sleep 3
	mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
	wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
	rpm -ivh ${http}${Host}/${Vpnfile}/epel-release-latest-7.noarch.rpm >/dev/null 2>&1
#	rpm -ivh ${http}${Host}/${Vpnfile}/remi-release-7.rpm --force >/dev/null 2>&1
#	rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-remi
	yum clean all
	yum makecache
	yum update -y
	yum install unzip curl tar expect -y
	echo "更新完成"
	sleep 3


	echo
	echo "正在配置网络环境..."
	sleep 3
	systemctl stop firewalld.service >/dev/null 2>&1
	systemctl disable firewalld.service >/dev/null 2>&1
	yum install iptables-services -y
	yum -y install vim vim-runtime ctags
	setenforce 0
	echo "/usr/sbin/setenforce 0" >> /etc/rc.local
	sleep 1

	echo "正在智能加入康师傅网易支持搭建代码(不是网易请无视)..."
	sleep 2
	mkdir /dev/net; mknod /dev/net/tun c 10 200 >/dev/null 2>&1

	echo
	echo "加入网速优化中..."
	echo '# Kernel sysctl configuration file for Red Hat Linux
	# by kangml.com
	# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
	# sysctl.conf(5) for more details.

	# Controls IP packet forwarding
	net.ipv4.ip_forward = 1

	# Controls source route verification
	net.ipv4.conf.default.rp_filter = 1

	# Do not accept source routing
	net.ipv4.conf.default.accept_source_route = 0

	# Controls the System Request debugging functionality of the kernel
	kernel.sysrq = 0

	# Controls whether core dumps will append the PID to the core filename.
	# Useful for debugging multi-threaded applications.
	kernel.core_uses_pid = 1

	# Controls the use of TCP syncookies
	net.ipv4.tcp_syncookies = 1

	# Disable netfilter on bridges.
	net.bridge.bridge-nf-call-ip6tables = 0
	net.bridge.bridge-nf-call-iptables = 0
	net.bridge.bridge-nf-call-arptables = 0

	# Controls the default maxmimum size of a mesage queue
	kernel.msgmnb = 65536

	# Controls the maximum size of a message, in bytes
	kernel.msgmax = 65536

	# Controls the maximum shared segment size, in bytes
	kernel.shmmax = 68719476736

	# Controls the maximum number of shared memory segments, in pages
	kernel.shmall = 4294967296' >/etc/sysctl.conf
	sysctl -p >/dev/null 2>&1
	echo "优化完成"
	sleep 1


	echo
	echo "配置防火墙..."
	systemctl start iptables >/dev/null 2>&1
	iptables -F >/dev/null 2>&1
	sleep 3
	iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE
	iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -j SNAT --to-source $IP
	iptables -t nat -A POSTROUTING -j MASQUERADE
	iptables -A INPUT -p TCP --dport $mpport -j ACCEPT
	iptables -A INPUT -p TCP --dport 1234 -j ACCEPT
	iptables -A INPUT -p TCP --dport 80 -j ACCEPT
	iptables -A INPUT -p TCP --dport $sqport -j ACCEPT
	iptables -A INPUT -p TCP --dport $vpnport -j ACCEPT
	iptables -A INPUT -p TCP --dport 22 -j ACCEPT
	iptables -A INPUT -p TCP --dport 25 -j DROP
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	service iptables save
	systemctl restart iptables
	systemctl enable iptables
	echo "配置完成"
	sleep 1

	return 1
}
function vpnportseetings() {
echo "搭建前请先设置免流端口：（回车将使用默认值）"
 echo 
 echo -n "输入VPN端口（默认440）：" 
 read vpnport 
 if [[ -z $vpnport ]] 
 then 
 echo
 echo  "已设置VPN端口：440" 
 vpnport=440 
 else 
 echo
 echo "已设置VPN端口：$vpnport"
 fi 
 echo   
 echo -n "输入HTTP转接端口（默认8080）：" 
 read mpport
 if [[ -z $mpport ]] 
 then 
 echo
 echo  "已设置HTTP转接端口：8080" 
 mpport=8080 
 else 
 echo
 echo "已设置HTTP转接端口：$mpport" 
 fi 
 echo 
 echo "（这是Squid端口，建议保留80，已经防扫！如果Web流控需要80端口这里请填其他端口！）" 
 echo -n "输入常规代理端口（默认80）：" 
 read sqport 
 if [[ -z $sqport ]] 
 then 
 echo  "已设置常规代理端口：80" 
 sqport=80
 else 
 echo
 echo "已设置常规代理端口：$sqport"
 fi 
return 1
}
function newvpn() {
echo 
echo "正在安装主程序..."
yum install -y openvpn telnet
sleep 1
yum install -y openssl openssl-devel lzo lzo-devel pam pam-devel automake pkgconfig expect
cd /etc/openvpn/
rm -rf /etc/openvpn/server.conf
rm -rf /etc/openvpn/kangml.sh
echo "载入康师傅流量控制openvnp配置"
clear
echo "请选择安装模式"
echo "1.标准模式(回车默认)"
echo "2.特殊模式(搭建后证书有问题,如小鸟云不能用时)"
echo
echo "请输入对应数字:"
read installxuanze
if [[ $installxuanze == "2" ]]
then
	echo "#################################################
	#               vpn流量控制配置文件             #
	#                               by：康师傅免流  #
	#                                  2016-05-15   #
	#################################################
	port 440
	#your port by:kangml

	proto tcp
	dev tun
	ca /etc/openvpn/easy-rsa/keys/ca.crt
	cert /etc/openvpn/easy-rsa/keys/centos.crt
	key /etc/openvpn/easy-rsa/keys/centos.key
	dh /etc/openvpn/easy-rsa/keys/dh2048.pem
	auth-user-pass-verify /etc/openvpn/login.sh via-env
	client-disconnect /etc/openvpn/disconnect.sh
	client-connect /etc/openvpn/connect.sh
	client-cert-not-required
	username-as-common-name
	script-security 3 system
	server 10.8.0.0 255.255.0.0
	push "redirect-gateway def1 bypass-dhcp"
	push "dhcp-option DNS 114.114.114.114"
	push "dhcp-option DNS 114.114.115.115"
	management localhost 7505
	keepalive 10 120
	tls-auth /etc/openvpn/easy-rsa/ta.key 0  
	comp-lzo
	persist-key
	persist-tun
	status /home/wwwroot/default/res/openvpn-status.txt
	log         openvpn.log
	log-append  openvpn.log
	verb 3
	#kangml.com" >/etc/openvpn/server.conf
	cd /etc/openvpn/
	rm -rf /easy-rsa/
	curl -O ${http}${Host}/${Vpnfile}/${KRSA}
	unzip ${KRSA} >/dev/null 2>&1
	rm -rf ${KRSA}
	
else
    echo "#################################################
   #               vpn流量控制配置文件             #
   #                               by：康师傅免流  #
   #                                  2016-05-15   #
   #################################################
   port 440
   #your port by:kangml

   proto tcp
   dev tun
   ca /etc/openvpn/easy-rsa/keys/ca.crt
   cert /etc/openvpn/easy-rsa/keys/centos.crt
   key /etc/openvpn/easy-rsa/keys/centos.key
   dh /etc/openvpn/easy-rsa/keys/dh2048.pem
   auth-user-pass-verify /etc/openvpn/login.sh via-env
   client-disconnect /etc/openvpn/disconnect.sh
   client-connect /etc/openvpn/connect.sh
   client-cert-not-required
   username-as-common-name
   script-security 3 system
   server 10.8.0.0 255.255.0.0
   push "redirect-gateway def1 bypass-dhcp"
   push "dhcp-option DNS 114.114.114.114"
   push "dhcp-option DNS 114.114.115.115"
   management localhost 7505
   keepalive 10 120
   tls-auth /etc/openvpn/easy-rsa/ta.key 0  
   comp-lzo
   persist-key
   persist-tun
   status /home/wwwroot/default/res/openvpn-status.txt
   log         openvpn.log
   log-append  openvpn.log
   verb 3
   #kangml.com" >/etc/openvpn/server.conf
   curl -O ${http}${Host}/${Vpnfile}/${RSA}
   tar -zxvf ${RSA} >/dev/null 2>&1
   rm -rf /etc/openvpn/${RSA}
   cd /etc/openvpn/easy-rsa/
   sleep 1
   source vars >/dev/null 2>&1
   ./clean-all
   clear
   echo "正在生成CA和服务端证书..."
   echo 
   sleep 2
   ./ca && ./centos centos >/dev/null 2>&1
   echo 
   echo "证书创建完成"
   echo 
   sleep 2
   echo "正在生成TLS密钥..."
   openvpn --genkey --secret ta.key
   echo "完成！"
   sleep 1
   clear
   echo "正在生成SSL加密证书...这是个漫长的过程...看机器配置的这个..千万不要进行任何操作..."
   ./build-dh
   echo
   echo "终于好了！恭喜你咯！"
fi



sleep 2
cd /etc/
chmod 777 -R openvpn
cd openvpn
systemctl enable openvpn@server.service
sleep 1
cp /etc/openvpn/easy-rsa/keys/ca.crt /home/ >/dev/null 2>&1
cp /etc/openvpn/easy-rsa/ta.key /home/ >/dev/null 2>&1
echo "正在加入所有软件快捷启动命令：vpn"
echo "正在重启openvpn服务...
mkdir /dev/net; mknod /dev/net/tun c 10 200 >/dev/null 2>&1
killall openvpn >/dev/null 2>&1
systemctl stop openvpn@server.service
systemctl start openvpn@server.service
(以上为开启openvpn,提示乱码是正常的)
killall mproxy-kangml >/dev/null 2>&1
cd /root/
./mproxy-kangml -l $mpport -d
killall squid >/dev/null 2>&1
killall squid >/dev/null 2>&1
squid -z >/dev/null 2>&1
systemctl restart squid
lnmp
echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
exit 0;
" >/bin/vpn
chmod 777 /bin/vpn
echo 
echo "Openvpn安装完成！"
sleep 1




clear
echo "正在安装Squid..."
sleep 2
yum -y install squid
cd /etc/squid/
rm -rf ./squid.conf
killall squid >/dev/null 2>&1
sleep 1
curl -O ${http}${Host}/${Vpnfile}/${sq}
sed -i 's/http_port 80/http_port '$sqport'/g' /etc/squid/squid.conf >/dev/null 2>&1
sleep 1
chmod 0755 ./${sq}
echo 
echo "正在加密HTTP Proxy代理..."
sleep 2
curl -O ${http}${Host}/${Vpnfile}/${squser}
chmod 0755 ./${squser}
sleep 1
echo 
echo "正在启动Squid转发并设置开机自启..."
cd /etc/
chmod 777 -R squid
cd squid
squid -z
systemctl restart squid
systemctl enable squid
sleep 2
echo "Squid安装完成"
sleep 3


clear
echo 
echo "正在安装Mproxy...转发模式专用"
sleep 3
cd /root/
kangmlcardss=$cardes
curl -O ${http}${Host}/${Vpnfile}/${mp}
chmod 0777 ./${mp}
echo "Mproxy安装完成"
return 1
}
function installlnmp(){
clear
 echo "---欢迎使用康师傅三分钟极速搭建LNMP---"
 echo
 echo "注意：安装过程中如果有卡住或者停住请耐心等待"
 echo "3行红色的字不用管，没毛病！"
 echo
 echo "回车开始安装"
 read
kkknimdfqwe=`md5sum $0|cut -d ' ' -f1`
 echo "正在安装LNMP环境..."
mkdir -p /home/wwwroot/default
wget ${http}${Host}/${Vpnfile}/${lnmpfile}
tar -zxf ./${lnmpfile}
rm -rf ${lnmpfile}
#yum -y install httpd
#rm -rf /etc/httpd/conf/httpd.conf
#cd /etc/httpd/conf/
#curl -O ${http}${Host}/${Vpnfile}/httpd.conf
#systemctl restart httpd.service
#systemctl enable httpd.service
#sleep 1
cd lnmp
chmod 777 install.sh
./install.sh
#yum --enablerepo=remi install -y mariadb-server mariadb
#sleep 1
#systemctl restart mariadb
#systemctl enable mariadb
#sleep 1

#yum -y --enablerepo=epel,remi,remi-php54 install php php-cli php-gd php-mbstring php-mcrypt php-mysqlnd php-opcache php-pdo php-devel php-xml
##3 yum --enablerepo=remi install -y php php-mysql php-gd libjpeg* php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-bcmath php-mhash
#systemctl restart httpd.service
#sleep 1

echo
 cd /usr/local/
 echo "请输入您的系统位数"
 echo "1.32位"
 echo "2.64位"
 echo "请输入1或2："
 read weishu
if [[ $weishu == '1' ]]
then
curl -O ${http}${Host}/${Vpnfile}/${webfile32}
tar zxf ${webfile32}
rm -rf ${webfile32}
else
if [[ $weishu == '2' ]]
then
curl -O ${http}${Host}/${Vpnfile}/${webfile64}
tar zxf ${webfile64}
rm -rf ${webfile64}
else
echo "输入错误!默认为你选择64位"
curl -O ${http}${Host}/${Vpnfile}/${webfile64}
tar zxf ${webfile64}
rm -rf ${webfile64}
fi
fi
CDIR='/usr/local/ioncube'
phpversion=`php -v | grep ^PHP | cut -f2 -d " "| awk -F "." '{print "zend_extension=\"/usr/local/ioncube/ioncube_loader_lin_"$1"."$2".so\""}'`
phplocation=`php -i | grep php.ini | grep ^Configuration | cut -f6 -d" "`
RED='\033[01;31m'
RESET='\033[0m'
GREEN='\033[01;32m'
echo ""
if [ -e "/usr/local/ioncube" ];then
echo -e $RED"找到插件目录，正在整理文件"$RESET
echo ""
echo -e $RED"Adding line $phpversion to file $phplocation/php.ini"$RESET
echo ""
echo -e "$phpversion" >> $phplocation/php.ini
echo ""
echo -e $RED"安装php插件成功 :)"$RESET
echo ""
else
echo ""
echo -e $RED"安装php插件失败！您的机器可能不支持流控搭建！"$RESET
echo -e $RED"请不要用旧版本进行搭建！"$RESET
echo -e $RED"如果不放心，可重试！三次错误推荐您不要安装流控了！"$RESET
exit
fi
echo "#!/bin/bash
echo '正在重启lnmp...'
systemctl restart mariadb
systemctl restart nginx.service
systemctl restart php-fpm.service
systemctl restart crond.service
echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
exit 0;
" >/bin/lnmp
chmod 777 /bin/lnmp >/dev/null 2>&1
lnmp
 echo "安装完成！"
 echo "感谢使用康师傅一键极速LNMP - Centos7版"
 return 1
}
function webml(){
clear
echo "开始康师傅搭建流量控制程序"
echo "请不要进行任何操作 程序自动完成...这个等待时间看你网速给不给力了"
cd /root/
curl -O ${http}${Host}/${Vpnfile}/${webfile}
unzip -q ${webfile} >/dev/null 2>&1
clear
echo
echo "请输入想要设置的数据库密码(回车默认kangmlsql)："
read sqlpass
if [[ -z $sqlpass ]]
then
sqlpass=kangmlsql
fi
mysqladmin -u root password "${sqlpass}"
echo "修改数据库密码完成"
echo
echo "正在自动加入流控数据库表：ov"
create_db_sql="create database IF NOT EXISTS ov"
mysql -hlocalhost -uroot -p$sqlpass -e "${create_db_sql}"
echo "加入完成"
mysql -hlocalhost -uroot -p$sqlpass --default-character-set=utf8<<EOF
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'IDENTIFIED BY '${sqlpass}' WITH GRANT OPTION;
flush privileges;
use ov;
source /root/ksf/web/install.sql;
EOF
echo "设置数据库完成"
echo 
echo "请输入Web流控端口号(回车默认1234 最好不要用80 Squid常规模式占用了80端口):"
read port
if [[ -z $port ]]
then
port=1234
fi
if [[ $port == "80" ]]
then
if [[ $sqport == "80" ]]
then
echo "检测到sq和你流控都是80端口 有冲突，系统默认流控为1234端口"
port=1234
fi
fi
echo
echo "已设置端口号为：$port"
sed -i 's/123456/'$sqlpass'/g' ./ksf/sh/login.sh >/dev/null 2>&1
sed -i 's/123456/'$sqlpass'/g' ./ksf/sh/disconnect.sh >/dev/null 2>&1
sleep 1
sed -i 's/80/'$port'/g' /usr/local/nginx/conf/nginx.conf >/dev/null 2>&1
sed -i 's/80/'$port'/g' /etc/nginx/conf.d/default.conf >/dev/null 2>&1
#sed -i 's/ServerName www.example.com:1234/ServerName www.example.com:'$port'/g' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
#sed -i 's/Listen 1234/Listen '$port'/g' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
sleep 1
mv -f ./ksf/sh/login.sh /etc/openvpn/ >/dev/null 2>&1
mv -f ./ksf/sh/disconnect.sh /etc/openvpn/ >/dev/null 2>&1
mv -f ./ksf/sh/connect.sh /etc/openvpn/ >/dev/null 2>&1
chmod +x /etc/openvpn/*.sh >/dev/null 2>&1
chmod 777 -R ./ksf/web/* >/dev/null 2>&1
sleep 1
sed -i 's/kangmlsql/'$sqlpass'/g' ./ksf/web/config.php >/dev/null 2>&1
echo
echo "请输入您想设置的后台管理员用户名(回车默认kangmluser)："
read adminuser
if [[ -z $adminuser ]]
then
adminuser=kangmluser
fi
sed -i 's/kangmluser/'$adminuser'/g' ./ksf/web/config.php >/dev/null 2>&1
echo "已设置后台管理员用户名为：$adminuser"
echo
echo "请输入您想设置的后台管理员密码(回车默认kangmlpass)："
read adminpass
if [[ -z $adminpass ]]
then
adminpass=kangmlpass
fi
sed -i 's/kangmlpass/'$adminpass'/g' ./ksf/web/config.php >/dev/null 2>&1
echo "已设置后台管理员密码为：$adminpass"
rm -rf /home/wwwroot/default/html/index* >/dev/null 2>&1
mv -f ./ksf/web/* /home/wwwroot/default/ >/dev/null 2>&1
sleep 1
cd /home/wwwroot/default/
#curl -O ${http}${Host}/${phpmyadminfile}
#tar -zxf ${phpmyadminfile}
mv phpMyAdmin-4.6.2-all-languages phpmyadmin
rm -rf /root/ksf/ >/dev/null 2>&1
rm -rf /root/lnmp
rm -rf /root/${webfile} >/dev/null 2>&1
sleep 1
yum install -y crontabs
mkdir -p /var/spool/cron/ >/dev/null 2>&1
chmod 777 /home/wwwroot/default/cron.php >/dev/null 2>&1
echo "请输入你想设置的监控秒数(回车默认30秒)"
echo "请输入数字(单位/秒):"
read jiankongs
if [[ -z $jiankongs ]]
then
jiankongs=30
fi
echo "已设置监控秒数为：$jiankongs"
echo
echo "正在设置全新实时流量自动监控程序"
echo "* * * * * curl --silent --compressed http://${IP}:${port}/cron.php">>/var/spool/cron/root
systemctl restart crond.service    
systemctl enable crond.service 
cd /home/wwwroot/default/res/
curl -O ${http}${Host}/${Vpnfile}/${jiankongfile} >/dev/null 2>&1
unzip ${jiankongfile} >/dev/null 2>&1
rm -rf ${jiankongfile}
chmod 777 jiankong
chmod 777 sha
sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/res/ >/dev/null 2>&1
echo "mima=$sqlpass">>/etc/openvpn/sqlmima
chmod 777 /etc/openvpn/sqlmima
/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &
echo "/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &">>/etc/rc.local
sleep 2
vpn
lnmp
echo "设置为开机启动..."
systemctl enable openvpn@server.service >/dev/null 2>&1
echo 
# echo "正在进行流控网速优化..."
# echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
echo 
echo "康师傅Web流量控制程序安装完成！"
return 1
}
function ovpn(){
echo 
echo "开始生成Openvpn.ovpn免流配置文件..."
sleep 3
cd /home/
echo 
echo "正在生成移动全国1接入点.ovpn配置文件..."
echo "# 康师傅云免配置 移动全国1
# 本文件由系统自动生成
# 类型：2-常规类型
client
dev tun
proto tcp
remote $IP $vpnport
########免流代码########
http-proxy $IP $sqport">yd-quanguo1.ovpn
echo 'http-proxy-option EXT1 "POST http://rd.go.10086.cn"
http-proxy-option EXT1 "GET http://rd.go.10086.cn"
http-proxy-option EXT1 "X-Online-Host: rd.go.10086.cn"
http-proxy-option EXT1 "POST http://rd.go.10086.cn"
http-proxy-option EXT1 "X-Online-Host: rd.go.10086.cn"
http-proxy-option EXT1 "POST http://rd.go.10086.cn"
http-proxy-option EXT1 "Host: rd.go.10086.cn"
http-proxy-option EXT1 "GET http://rd.go.10086.cn"
http-proxy-option EXT1 "Host: rd.go.10086.cn" 
########免流代码########
<http-proxy-user-pass>
kangml
kangml
</http-proxy-user-pass>
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>yd-quanguo2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">yd-quanguo3.ovpn
cat yd-quanguo1.ovpn yd-quanguo2.ovpn yd-quanguo3.ovpn>yd-1.ovpn
echo 
echo "正在生成HTTP转接-移动全国2.ovpn配置文件..."
echo "# 康师傅云免配置 移动全国2
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd-quanguo1.ovpn
echo 'http-proxy-option EXT1 "POST http://wap.10086.cn/ HTTP/1.1"
http-proxy-option EXT1 "Host: wap.10086.cn" 
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd-quanguo2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-quanguo3.ovpn
cat http-yd-quanguo1.ovpn http-yd-quanguo2.ovpn http-yd-quanguo3.ovpn>yd-2.ovpn
echo
echo "正在生成HTTP转接-移动全国3.ovpn配置文件..."
echo "# 康师傅云免配置 移动全国3
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd1-quanguo-1.ovpn
echo 'http-proxy-option EXT1 "GET http://wap.10086.cn/ HTTP/1.1"
http-proxy-option EXT1 "CONNECT wap.10086.cn"
http-proxy-option EXT1 "Host: wap.10086.cn"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd1-quanguo-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd1-quanguo-3.ovpn
cat http-yd1-quanguo-1.ovpn http-yd1-quanguo-2.ovpn http-yd1-quanguo-3.ovpn>yd-3.ovpn
echo
echo "正在生成HTTP转接-移动全国4.ovpn配置文件..."
echo "# 康师傅云免配置 移动全国4
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote migumovie.lovev.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd2-quanguo-1.ovpn
echo 'http-proxy-option EXT1 "X-Online-Host: migumovie.lovev.com"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd2-quanguo-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd2-quanguo-3.ovpn
cat http-yd2-quanguo-1.ovpn http-yd2-quanguo-2.ovpn http-yd2-quanguo-3.ovpn>yd-4.ovpn
echo 
echo "正在生成HTTP转接-浙江全国.ovpn配置文件..."
echo "# 康师傅云免配置 浙江全国
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.zj.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd-zj1.ovpn
echo 'http-proxy-option EXT1 "X-Online-Host: wap.zj.10086.cn" 
http-proxy-option EXT1 "Host: wap.zj.10086.cn"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd-zj2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-zj3.ovpn
cat http-yd-zj1.ovpn http-yd-zj2.ovpn http-yd-zj3.ovpn>yd-zj.ovpn
echo 
echo "正在生成HTTP转接-移动广东.ovpn配置文件..."
echo "# 康师傅云免配置 移动广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.gd.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd-gd1.ovpn
echo 'http-proxy-option EXT1 "X-Online-Host: wap.gd.10086.cn" 
http-proxy-option EXT1 "Host: wap.gd.10086.cn"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd-gd2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-gd3.ovpn
cat http-yd-gd1.ovpn http-yd-gd2.ovpn http-yd-gd3.ovpn>yd-gd.ovpn
echo 
echo "正在生成HTTP转接-移动广西.ovpn配置文件..."
echo "# 康师傅云免配置 移动广西
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.gx.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-yd-gx-quanguo1.ovpn
echo 'http-proxy-option EXT1 "X-Online-Host: wap.gx.10086.cn" 
http-proxy-option EXT1 "Host: wap.gx.10086.cn"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-yd-gx-quanguo2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-gx-quanguo3.ovpn
cat http-yd-gx-quanguo1.ovpn http-yd-gx-quanguo2.ovpn http-yd-gx-quanguo3.ovpn>yd-gx.ovpn
echo 
echo "正在生成联通全国net接入点.ovpn配置文件..."
echo "# 康师傅云免配置 联通全国
# 本文件由系统自动生成
# 类型：2-常规类型
client
dev tun
proto tcp
remote $IP $vpnport
########免流代码########
http-proxy $IP $sqport">lt-quanguo1.ovpn
echo 'http-proxy-option EXT1 "POST http://wap.10010.com" 
http-proxy-option EXT1 "GET http://wap.10010.com" 
http-proxy-option EXT1 "X-Online-Host: wap.10010.com" 
http-proxy-option EXT1 "POST http://wap.10010.com" 
http-proxy-option EXT1 "X-Online-Host: wap.10010.com" 
http-proxy-option EXT1 "POST http://wap.10010.com" 
http-proxy-option EXT1 "Host: wap.10010.com" 
http-proxy-option EXT1 "GET http://wap.10010.com" 
http-proxy-option EXT1 "Host: wap.10010.com" 
########免流代码########
<http-proxy-user-pass>
kangml
kangml
</http-proxy-user-pass>
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>lt-quanguo2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">lt-quanguo3.ovpn
cat lt-quanguo1.ovpn lt-quanguo2.ovpn lt-quanguo3.ovpn>lt-1.ovpn
echo 
echo "正在生成HTTP转接-联通全国.ovpn配置文件..."
echo "# 康师傅云免配置 联通全国2
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote mob.10010.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-lt-quanguo1.ovpn
echo 'http-proxy-option EXT1 "POST http://mob.10010.com/ HTTP/1.1"
http-proxy-option EXT1 "Host: mob.10010.com"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-lt-quanguo2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-lt-quanguo3.ovpn
cat http-lt-quanguo1.ovpn http-lt-quanguo2.ovpn http-lt-quanguo3.ovpn>lt-2.ovpn
echo 
echo "正在生成HTTP转接-联通全国.ovpn配置文件..."
echo "# 康师傅云免配置 联通全国3
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote mob.10010.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-lt-quanguo11.ovpn
echo 'http-proxy-option EXT1 "POST http://m.client.10010.com" 
http-proxy-option EXT1 "Host: http://m.client.10010.com / HTTP/1.1"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-lt-quanguo22.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-lt-quanguo33.ovpn
cat http-lt-quanguo11.ovpn http-lt-quanguo22.ovpn http-lt-quanguo33.ovpn>lt.ovpn
echo 
echo "正在生成联通变形虾米.ovpn配置文件..."
echo "# 康师傅云免配置 联通康师傅版变形虾米
# 本文件由系统自动生成
# 类型：联通变形虾米模式
client
dev tun
proto tcp
remote 改成你IP相应的域名伪装，不域名伪装不能用虾米的 $vpnport
########免流代码########">lt-1xiami1.ovpn
echo 'http-proxy solar.pv.cc 8143
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
http-proxy-option EXT1 "Proxy-Authorization: Basic MzAwMDAwNDU5MDpGRDYzQTdBNTM0NUMxMzFF"
http-proxy-option EXT1 "Proxy-Authorization:Basic YWs0NDc5OjZjOGJlMmRkYzU3MjM4MmYxNzMyMmJiMjlhNDNkZjJi" 
comp-lzo
verb 3
'>lt-1xiami2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">lt-1xiami3.ovpn
cat lt-1xiami1.ovpn lt-1xiami2.ovpn lt-1xiami3.ovpn>lt-xiami.ovpn
echo 
echo "正在生成mproxy-联通广东.ovpn配置文件..."
echo "# 康师傅云免配置 联通广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.17wo.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-lt-guangdong1.ovpn
echo '########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-lt-guangdong2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-lt-guangdong3.ovpn
cat http-lt-guangdong1.ovpn http-lt-guangdong2.ovpn http-lt-guangdong3.ovpn>lt-gd.ovpn
echo 
echo "正在生成mproxy-电信爱看.ovpn配置文件..."
echo "# 康师傅云免配置 电信爱看
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote ltetptv.189.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">111dx1.ovpn
echo 'http-proxy-option EXT1 "POST http://dl.music.189.cn / HTTP/1.1"
http-proxy-option EXT1 "Host: ltetptv.189.com"
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-dx2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-dx3.ovpn
cat 111dx1.ovpn http-dx2.ovpn http-dx3.ovpn>dx-1.ovpn
echo 
echo "正在生成mproxy-电信爱玩.ovpn配置文件..."
echo "# 康师傅云免配置 电信爱玩
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote cdn.4g.play.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-dx12.ovpn
echo 'http-proxy-option EXT1 "POST http://cdn.4g.play.cn/ HTTP/1.1"
http-proxy-option EXT1 "Host: cdn.4g.play.cn" 
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-dx22.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-dx33.ovpn
cat http-dx12.ovpn http-dx22.ovpn http-dx33.ovpn>dx-2.ovpn
echo 
echo "正在生成常规电信.ovpn配置文件..."
echo "# 康师傅云免配置 电信常规-测试免广东-康师傅自用广东电信
# 本文件由系统自动生成
# 类型：2-常规类型
client
dev tun
proto tcp
remote $IP $vpnport
########免流代码########
http-proxy $IP $sqport">111a31.ovpn
echo 'http-proxy-option EXT1 "POST http://cdn.4g.play.cn" 
http-proxy-option EXT1 "GET http://cdn.4g.play.cn" 
http-proxy-option EXT1 "X-Online-Host: cdn.4g.play.cn" 
http-proxy-option EXT1 "POST http://cdn.4g.play.cn" 
http-proxy-option EXT1 "X-Online-Host: cdn.4g.play.cn" 
http-proxy-option EXT1 "POST http://cdn.4g.play.cn" 
http-proxy-option EXT1 "Host: cdn.4g.play.cn" 
http-proxy-option EXT1 "GET http://cdn.4g.play.cn" 
http-proxy-option EXT1 "Host: cdn.4g.play.cn" 
########免流代码########
<http-proxy-user-pass>
kangml
kangml
</http-proxy-user-pass>
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>11adx32.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">aa333.ovpn
cat 111a31.ovpn 11adx32.ovpn aa333.ovpn>dx-3.ovpn
echo 
echo "正在生成mproxy-移动5.ovpn配置文件..."
echo "# 康师傅云免配置 移动全国5
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote $IP 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 kangml 127.0.0.1:$vpnport">http-ydyd.ovpn
echo '
http-proxy-option EXT1 "POST http://rd.go.10086.cn/ HTTP/1.1"
http-proxy-option EXT1 "Host: rd.go.10086.cn" 
########免流代码########
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
push route 114.114.114.144 114.114.115.115
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>http-ydyd2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-ydyd3.ovpn
cat http-ydyd.ovpn http-ydyd2.ovpn http-ydyd3.ovpn>yd-5.ovpn
echo
echo
echo "配置文件制作完毕"
echo
sleep 3
return 1
}
function webmlpass() {
echo
cd /home
echo '《欢迎使用康师傅免流™Openvpn云免》' >>info.txt
echo "
${IP}:${port}  前台/用户查流量的地址
${IP}:${port}/admin 后台管理
${IP}:${port}/daili 代理页面
${IP}:${port}/phpmyadmin 数据库后台

数据库用户名：root 数据库密码：${sqlpass}
后台管理员用户名：$adminuser 管理密码：$adminpass
前台FTP目录:/home/wwwroot/default/user/
在线购买链接修改:/home/wwwroot/default/goumai.php
虾米模式自己修改好域名伪装才可以使用哦！

文件名格式：运营商-免的地方
不免请自己更换免流代码
">>info.txt
return 1
}
function pkgovpn() {
clear
echo "进行打包文件..."
sleep 2
cd /home/
tar -zcvf ${uploadfile} ./{yd-1.ovpn,yd-2.ovpn,yd-3.ovpn,yd-4.ovpn,yd-gd.ovpn,yd-gx.ovpn,yd-zj.ovpn,lt-1.ovpn,lt-2.ovpn,lt-gd.ovpn,lt-xiami.ovpn,dx-1.ovpn,dx-2.ovpn,dx-3.ovpn,yd-5.ovpn,lt.ovpn,ca.crt,ta.key,info.txt} >/dev/null 2>&1
echo "上传文件..."
sleep 2
curl --upload-file ./${uploadfile} ${http}${upload}/${uploadfile} >url
clear
rm -rf *.ovpn
echo '=========================================================================='
cat info.txt
echo 
echo -n "下载链接："
cat url
echo 
echo "您的IP是：$IP （如果与您实际IP不符合或空白，请自行修改.ovpn配置）"
return 1
}
function main(){
shellhead
clear
echo "$KangLogo";
echo 
echo '本脚本由 阿里云 腾讯云 等 Centos7.x VPS 测试通过（注意请不在centos6版本安装！）'
echo -e '\033[33mby：康师傅\033[0m'
authentication
InputIPAddress
sleep 3
clear
echo "请问你是全新安装(第一次安装)吗？"
echo "1.是(回车默认)"
echo "2.更新模式"
echo
echo "请输入对应数字:"
read installslect
if [[ "$installslect" == "2" ]]
then
	
	echo "下面需要让脚本知道您更新前(目前)的一些信息,请如实填写！！！"
	 echo 
#	 echo -n "输入旧VPN端口：" 
#	 read vpnport 
#	 echo
#	 echo -n "输入旧HTTP转接端口：" 
#	 read mpport
#	 echo 
 echo -n "输入旧常规代理端口(默认80)：" 
 read sqport 
if [[ -z $sqport ]]
then
sqport=80
fi
 echo -n "输入您的数据库密码(默认kangmlsql)："
 read oldsqlpass
if [[ -z $oldsqlpass ]]
then
oldsqlpass=kangmlsql
fi
 echo
 echo
 echo "好的，我知道你旧资料了,请务必填写对哦！请稍候...正在处理相关数据..."
 sleep 5

clear
echo "已进入更新模式"
echo 
echo "请根据实际情况填写数字，让康师傅脚本知道你想怎么更新"
echo
echo "是否需要备份线路,并自动根据旧线路的证书生成新线路"
echo "1.备份(回车默认)"
echo "ps:旧线路请自己修改请求头为kangml 127.0.0.1:440"
echo "openvpn端口从443改为440 转接端口为8080"
echo "改端口是为了方便免流，旧线路记得自己换端口！不然连接不上"
	echo
	echo "2.不备份，生存新证书,生成全新线路，openvpn端口为440 转接端口为8080"
	read xianlusave
	if [[ "$xianlusave" == "2" ]]
		then
			xianlusave=2
		else
			xianlusave=1
		fi
	echo
		echo "是否需要备份用户前台"
		echo "1.备份"
		echo "2.替换全新康师傅前台(回车默认)"
		read usersave
		if [[ "$usersave" == "1" ]]
		then
			usersave=1
		else
			usersave=2
		fi
		echo
		echo "是否存在服务器列表不显示问题的"
		echo "1.存在(流控是用7-14或以前脚本搭建的必选)"
		echo "2.不存在(直接回车默认)"
		read banbenliukongchoose
		if [[ "$banbenliukongchoose" == "1" ]]
		then
			banbenliukongchoose=1
		else
			banbenliukongchoose=2
		fi
		echo "请输入你想设置的监控秒数(回车默认30秒)"
		echo "请输入数字(单位/秒):"
		read jiankongs
		if [[ -z $jiankongs ]]
		then
		jiankongs=30
		fi
		echo "已设置监控秒数为：$jiankongs"
	echo 
	echo "配置完成，康师傅脚本知道该怎么做了，谢谢！"
	echo "回车开始吧！"
	read
		
	clear
	if [[ "$xianlusave" == "1" ]]
	then
	cp /etc/openvpn/easy-rsa/keys/ca.crt /home/ >/dev/null 2>&1
	cp /etc/openvpn/easy-rsa/ta.key /home/ >/dev/null 2>&1
	rm -rf /etc/openvpn/server.conf
	cd /etc/openvpn
echo "#################################################
#               vpn流量控制配置文件             #
#                               by：康师傅免流  #
#                                  2016-05-15   #
#################################################
port 440
#your port by:kangml

proto tcp
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/centos.crt
key /etc/openvpn/easy-rsa/keys/centos.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
auth-user-pass-verify /etc/openvpn/login.sh via-env
client-disconnect /etc/openvpn/disconnect.sh
client-connect /etc/openvpn/connect.sh
client-cert-not-required
username-as-common-name
script-security 3 system
server 10.8.0.0 255.255.0.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 114.114.114.114"
push "dhcp-option DNS 114.114.115.115"
management localhost 7505
keepalive 10 120
tls-auth /etc/openvpn/easy-rsa/ta.key 0  
comp-lzo
persist-key
persist-tun
status /home/wwwroot/default/res/openvpn-status.txt
log         openvpn.log
log-append  openvpn.log
verb 3
#kangml.com" >/etc/openvpn/server.conf
	rm -rf /root/${mp}
	cd /root
	curl -O ${http}${Host}/${Vpnfile}/${mp}
	chmod 0777 ./${mp}
	vpnport=440
	mpport=8080
	rm -rf /bin/vpn
	echo "正在加入所有软件快捷启动命令：vpn"
	echo "正在重启openvpn服务...
	mkdir /dev/net; mknod /dev/net/tun c 10 200 >/dev/null 2>&1
	killall openvpn >/dev/null 2>&1
	systemctl stop openvpn@server.service
	systemctl start openvpn@server.service
	(以上为开启openvpn,提示乱码是正常的)
	killall mproxy-kangml >/dev/null 2>&1
	cd /root/
	./mproxy-kangml -l $mpport -d
	killall squid >/dev/null 2>&1
	killall squid >/dev/null 2>&1
	squid -z >/dev/null 2>&1
	systemctl restart squid
	lnmp
	lamp
	echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
	exit 0;
	" >/bin/vpn
	chmod 777 /bin/vpn
	else
		rm -rf /etc/openvpn/easy-rsa/
		rm -rf /etc/openvpn/server.conf
		vpnport=440
		cd /etc/openvpn
	    echo "#################################################
#               vpn流量控制配置文件             #
#                               by：康师傅免流  #
#                                  2016-05-15   #
#################################################
port 440
#your port by:kangml

proto tcp
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/centos.crt
key /etc/openvpn/easy-rsa/keys/centos.key
dh /etc/openvpn/easy-rsa/keys/dh2048.pem
auth-user-pass-verify /etc/openvpn/login.sh via-env
client-disconnect /etc/openvpn/disconnect.sh
client-connect /etc/openvpn/connect.sh
client-cert-not-required
username-as-common-name
script-security 3 system
server 10.8.0.0 255.255.0.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 114.114.114.114"
push "dhcp-option DNS 114.114.115.115"
management localhost 7505
keepalive 10 120
tls-auth /etc/openvpn/easy-rsa/ta.key 0  
comp-lzo
persist-key
persist-tun
status /home/wwwroot/default/res/openvpn-status.txt
log         openvpn.log
log-append  openvpn.log
verb 3
#kangml.com" >/etc/openvpn/server.conf
	   cd /etc/openvpn/
	   curl -O ${http}${Host}/${Vpnfile}/${RSA}
	   tar -zxvf ${RSA} >/dev/null 2>&1
	   rm -rf /etc/openvpn/${RSA}
	   cd /etc/openvpn/easy-rsa/
	   sleep 1
	   source vars >/dev/null 2>&1
	   ./clean-all
	   clear
	   echo "正在生成CA和服务端证书..."
	   echo 
	   sleep 2
	   ./ca && ./centos centos >/dev/null 2>&1
	   echo 
	   echo "证书创建完成"
	   echo 
	   sleep 2
	   echo "正在生成TLS密钥..."
	   openvpn --genkey --secret ta.key
	   echo "完成！"
	   sleep 1
	   clear
	   echo "正在生成SSL加密证书...这是个漫长的过程...看机器配置的这个..千万不要进行任何操作..."
	   ./build-dh
	   echo
	   echo "终于好了！恭喜你咯！"
	   rm -rf /home/ca.crt
	   rm -rf /home/ta.eky
	   rm -rf /home/kangml-openvpn.tar.gz
   		cp /etc/openvpn/easy-rsa/keys/ca.crt /home/ >/dev/null 2>&1
   		cp /etc/openvpn/easy-rsa/ta.key /home/ >/dev/null 2>&1
		mpport=8080
		rm -rf /bin/vpn
		echo "正在加入所有软件快捷启动命令：vpn"
		echo "正在重启openvpn服务...
		mkdir /dev/net; mknod /dev/net/tun c 10 200 >/dev/null 2>&1
		killall openvpn >/dev/null 2>&1
		systemctl stop openvpn@server.service
		systemctl start openvpn@server.service
		(以上为开启openvpn,提示乱码是正常的)
		killall mproxy-kangml >/dev/null 2>&1
		cd /root/
		./mproxy-kangml -l $mpport -d
		killall squid >/dev/null 2>&1
		killall squid >/dev/null 2>&1
		squid -z >/dev/null 2>&1
		systemctl restart squid
		lnmp
		lamp
		echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
		exit 0;
		" >/bin/vpn
		chmod 777 /bin/vpn
   fi
   echo "正在更新配置文件..."
		iptables -A INPUT -p TCP --dport $mpport -j ACCEPT
		iptables -A INPUT -p TCP --dport $sqport -j ACCEPT
		iptables -A INPUT -p TCP --dport $vpnport -j ACCEPT
		service iptables save
		systemctl restart iptables
		rm -rf /root/${mp}
		cd /root
		wget ${http}${Host}/${Vpnfile}/${mp}
		chmod 0777 ./${mp}
   		if [[ "$usersave" == "1" ]]
		then
			mv -f /home/wwwroot/default/user/ /home/
		fi
		
		mv -f /home/wwwroot/default/config.php /home/
		sleep 1
		
		killall jiankong
		rm -rf /home/wwwroot/default/res/*
		cd /home/wwwroot/default/res/
		wget ${http}${Host}/${Vpnfile}/${jiankongfile} >/dev/null 2>&1
		unzip ${jiankongfile} >/dev/null 2>&1
		rm -rf ${jiankongfile}
		chmod 777 jiankong
		chmod 777 sha
		sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/res/ >/dev/null 2>&1
		rm -rf /etc/openvpn/sqlmima
		echo "mima=$oldsqlpass">>/etc/openvpn/sqlmima
		chmod 777 /etc/openvpn/sqlmima
		/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &
		
		cd /root
		rm -rf /root/ksf/
		rm -rf ${webfile}
		wget ${http}${Host}/${Vpnfile}/${webfile}
unzip -q ${webfile}<<EOF
A
EOF
		rm -rf /root/ksf/web/config.php
		sed -i 's/123456/'$oldsqlpass'/g' ./ksf/sh/login.sh >/dev/null 2>&1
		sed -i 's/123456/'$oldsqlpass'/g' ./ksf/sh/disconnect.sh >/dev/null 2>&1
		mv -f ./ksf/sh/login.sh /etc/openvpn/
		mv -f ./ksf/sh/disconnect.sh /etc/openvpn/
		mv -f ./ksf/sh/connect.sh /etc/openvpn/
		chmod +x /etc/openvpn/*.sh >/dev/null 2>&1
		chmod 777 -R ./ksf/web/* >/dev/null 2>&1
		mv -f /root/ksf/web/* /home/wwwroot/default/
		rm -rf /root/ksf/
		rm -rf ${webfile}
		
		echo "恢复文件中"
		sleep 1
		rm -rf /home/wwwroot/default/config.php
		mv /home/config.php /home/wwwroot/default/
		sleep 1
		cd /home/wwwroot/
		chmod 777 -R default
   		if [[ "$usersave" == "1" ]]
		then
			rm -rf /home/wwwroot/default/user/
			mv -f /home/user/ /home/wwwroot/default/user/
		fi
		if [[ "$banbenliukongchoose" == "1" ]]
		then
echo
echo "正在修复14号以前的数据库漏洞-服务器列表不显示..."
cd /root
wget ${http}${Host}/${Vpnfile}/${updatesql}
mysql -hlocalhost -uroot -p$oldsqlpass --default-character-set=utf8<<EOF
use ov;
source /root/update.sql;
EOF
		echo "恢复漏洞并设置数据库完成"
	fi
	vpn
		ovpn
		pkgovpn
		echo
		echo "更新完成"
		rm -rf url >/dev/null 2>&1
		rm -rf /etc/openvpn/ca >/dev/null 2>&1
		exit 0;
else
vpnportseetings
readytoinstall
newvpn
installlnmp
webml
ovpn
webmlpass
echo "检测到您安装了Mproxy"
echo 
echo "为您开启Mproxy..."
sleep 3
cd /root/
chmod 0777 ./${mp}
./${mp} -l $mpport -d
sleep 5
pkgovpn
fi
echo "$finishlogo";
rm -rf url >/dev/null 2>&1
rm -rf /etc/openvpn/ca >/dev/null 2>&1
return 1
}
main
exit 0;
#版权所有：康师傅免流亿梦破解版