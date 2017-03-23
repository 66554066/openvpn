#!/bin/bash
# 本脚本由大猫制作
# 作者 大猫&掌握核心技术
function shellhead() {
	ulimit -c 0
	rm -rf $0 
	yum install curl -y
    DmgLogo='
==========================================================================
                                                                         
               大猫哥免流-Web流控系统 云免服务器一键搭建                      
                  Powered by dmkuai.com 2016                          
                      All Rights Reserved   
                    Cracked by:STAR-星辰	
                    欢迎加入流控破解基友群：
                        302742839
                                                                         
                                by 大猫哥 2016-08-27                     
==========================================================================';
	errorlogo='
==========================================================================
                        服务验证失败，安装被终止                                           
               大猫哥免流-Web流控系统 云免服务器一键搭建                      
                  Powered by dmkuai.com 2016                          
                      All Rights Reserved                                
                                                                         
                                by 大猫哥 2016-08-27                     
==========================================================================';
	finishlogo='
==========================================================================
                                                                         
               大猫哥免流-Web流控系统 云免服务器一键搭建                      
                  Powered by dmkuai.com 2016                          
                      All Rights Reserved      
                    Cracked by：辣鸡小白 兔		
                    欢迎加入流控破解基友群：
                        610530156					
                                                                         
                                by 大猫哥 2016-08-27                     
==========================================================================';
	keyerrorlogo='
==========================================================================
                      验证码输入错误，请重新运行                                            
               大猫哥免流-Web流控系统 云免服务器一键搭建                      
                           流量控制安装失败                          
                         All Rights Reserved                                
                                                                         
                                by 大猫哥 2016-08-27                     
==========================================================================';
	http="http://"; 
	Vpnfile=`curl -s http://dmkuai.com/Dmg-mulu`;
	sq=squid.conf;
	www=www.conf;
	php=atomic-ceshi-2;
	mp=udp.c;
	author=author-Dmg.tar.gz
	RSA=wz-easy-rsa.tar.gz;
	Host='dmkuai.com';
	IP=`curl -s http://members.3322.org/dyndns/getip`;
	squser=auth_user;
	mysqlip='null';
	KRSA=easy-rsa.zip;
	webupdatefile='Dmg-web-update.zip';
	webfile32='ioncube-32.tar.gz';
	webfile64='ioncube_loaders-64.tar.gz';
	phpmyadminfile='phpMyAdmin-4.0.10.15-all-languages.tar.gz';
	key='530723896';
	upload=transfer.sh;
	jiankongfile='jiankong-6.zip';
	lnmpfile='Dmg-ceshi-lnmp.tar.gz';
	webfile='dmg-web-6.zip'; 
	uploadfile=Dmg-dmkuai-$RANDOM.tar.gz;
	wget_host="zmker.oss-cn-shanghai.aliyuncs.com"
	files="files_v5"
	web_path="/home/wwwroot/default/"
	return 1
	qhm="530723896"
}
    function authentication() {
    echo -n -e "请输入我们的群号码 [\033[32m $key \033[0m] ："
    read PASSWD
    readkey=$PASSWD
    if [[ ${readkey%%\ *} == $key ]]
    then
        echo 
		echo -e '\033[32m验证成功！\033[0m即将进行下一部操作...'
		sleep 1
    else
        echo
		echo -e '\033[31m秘钥错误  \033[0m'
		echo -e '\033[31m验证失败 ，请重新尝试！  \033[0m'
		echo -e '\033[33m================☆☆========================================================\033[0m'
		echo -e '\033[33m		大猫哥免流™服务验证失败，安装被终止\033[0m'
		echo -e '\033[33m			Powered by dmkuai.com 2015-2016\033[0m'
		echo -e '\033[33m			All Rights Reserved \033[0m'
		echo -e '\033[33m		官方网址：http://dmkuai.com/ \033[0m'
		echo -e '\033[33m		我们的交流群：383503746	  欢迎你的加入！\033[0m'
		echo -e '\033[33m		秘钥验证失败，请核对秘钥是否正确！\033[0m'
		echo -e '\033[34m================☆☆========================================================\033[0m'
		sleep 3

exit
fi
return 1
}
function InputIPAddress() {

echo 

	if [[ "$IP" == '' ]]; then
		echo '抱歉！当前无法检测到您的IP';
		read -p '请输入您的公网IP:' IP;
		[[ "$IP" == '' ]] && InputIPAddress;
	fi;
	[[ "$IP" != '' ]] && 
						 echo -e 'IP状态：			  [\033[32m  OK  \033[0m]'
						 echo -e '您的IP是:' && echo $IP;	
						 echo
	return 1
}

function readytoinstall() {
	echo 
	echo "开始整理安装环境..."
	systemctl stop openvpn@server.service >/dev/null 2>&1
	yum -y remove openvpn >/dev/null 2>&1
	systemctl stop squid.service >/dev/null 2>&1
	yum -y remove squid >/dev/null 2>&1
	killall mproxy-1 >/dev/null 2>&1
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
	yum -y install net-tools lsof >/dev/null 2>&1
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
	echo "系统正在检查并更新程序，请耐心等待..."
	echo "请注意：系统正在后台更新软件以及源，请耐心等待10分钟左右！"
	echo "具体时间看您服务器速度决定，请耐心等待！"
	sleep 3
	mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup >/dev/null 2>&1
	wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo >/dev/null 2>&1
	rpm -ivh ${http}${Host}/${Vpnfile}/epel-release-latest-7.noarch.rpm >/dev/null 2>&1
	yum clean all >/dev/null 2>&1
	yum makecache >/dev/null 2>&1
	yum update -y >/dev/null 2>&1
	yum install unzip curl tar expect -y >/dev/null 2>&1
	echo "更新完成"
	sleep 1
	echo
	echo "正在配置网络环境..."
	sleep 3
	systemctl stop firewalld.service >/dev/null 2>&1
	systemctl disable firewalld.service >/dev/null 2>&1
	yum install iptables-services -y >/dev/null 2>&1
	yum -y install vim vim-runtime ctags >/dev/null 2>&1
	setenforce 0 >/dev/null 2>&1 
	sed -i "s|SELINUX=enforcing|SELINUX=disabled|" /etc/selinux/config
	echo "/usr/sbin/setenforce 0" >> /etc/rc.local >/dev/null 2>&1
	sleep 1
	echo
	echo "正在优化系统性能..."
	echo '# Kernel sysctl configuration file for Red Hat Linux
	# by dmkuai.com
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
	echo
	echo -e "正在配置防火墙"
	systemctl start iptables >/dev/null 2>&1
	iptables -F >/dev/null 2>&1
	sleep 3
	iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE
	iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -j SNAT --to-source $IP
	iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o eth0 -j MASQUERADE
	iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -j SNAT --to-source $IP
	iptables -t nat -A POSTROUTING -j MASQUERADE
	iptables -A INPUT -p TCP --dport $mpport -j ACCEPT
	iptables -A INPUT -p TCP --dport 808 -j ACCEPT
	iptables -A INPUT -p UDP --dport 138 -j ACCEPT
	iptables -A INPUT -p TCP --dport 138 -j ACCEPT
	iptables -A INPUT -p TCP --dport 366 -j ACCEPT
	iptables -A INPUT -p TCP --dport 351 -j ACCEPT
	iptables -A INPUT -p TCP --dport 3389 -j ACCEPT
	iptables -A INPUT -p TCP --dport 524 -j ACCEPT
	iptables -A INPUT -p TCP --dport 440 -j ACCEPT
	iptables -A INPUT -p TCP --dport 443 -j ACCEPT
	iptables -A INPUT -p TCP --dport 1026 -j ACCEPT
	iptables -A INPUT -p TCP --dport 8081 -j ACCEPT
	iptables -A INPUT -p TCP --dport 180 -j ACCEPT
	iptables -A INPUT -p TCP --dport 53 -j ACCEPT
	iptables -A INPUT -p TCP --dport 80 -j ACCEPT
	iptables -A INPUT -p TCP --dport $sqport -j ACCEPT
	iptables -A INPUT -p TCP --dport $vpnport -j ACCEPT
	iptables -A INPUT -p TCP --dport 22 -j ACCEPT
	iptables -A INPUT -p TCP --dport 25 -j DROP
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	service iptables save >/dev/null 2>&1
	systemctl restart iptables >/dev/null 2>&1
	systemctl enable iptables >/dev/null 2>&1
	echo
	echo "配置完成"
	sleep 1

	
	cd /etc/
	curl -o openvpn-2.3.2-4.el7.x86_64.rpm ${http}${Host}/${Vpnfile}/openvpn-2.3.2-4.el7.x86_64.rpm >/dev/null 2>&1
	rpm -ivh openvpn-2.3.2-4.el7.x86_64.rpm
	if [ ! -f "/etc/openvpn-2.3.2-4.el7.x86_64.rpm" ];
	then
		rm -f openvpn-2.3.2-4.el7.x86_64.rpm	
	fi
	if [ ! -e "/usr/sbin/openvpn" ];
	then
		yum install openvpn -y
	fi
	
	
	return 1
}

function vpnportseetings() {
 clear
 echo "自定义设置端口（以下设置可直接回车使用默认值）"
 
 echo -n "输入VPN端口（默认440）：" 
 read vpnport 
 if [[ -z $vpnport ]] 
 then 
 echo -e '[\033[32m  已设置VPN端口：440  \033[0m]';
 vpnport=440
 else 
 echo -e '[\033[32m  已设置VPN端口：  \033[0m]'$vpnport;
 fi 
 
 echo
 
 echo "（此端口设置复杂的端口有效避免被扫流量问题，中国移动请保留8080）"
 echo -n "输入HTTP转接端口（默认8080）：" 
 read mpport
 if [[ -z $mpport ]] 
 then 
  echo -e '[\033[32m  已设置HTTP转接端口：8080  \033[0m]';
 mpport=8080 
 else 
 echo -e '[\033[32m  已设置HTTP转接端口：  \033[0m]'$mpport;
 fi 

 echo
 
 echo "此端口建议保留80，已经防扫！如果Web流控需要80端口这里请填其他端口！" 
 echo -n "输入常规代理端口（默认80）：" 
 read sqport 
 if [[ -z $sqport ]] 
 then 
  echo -e '[\033[32m  已设置常规代理端口：80  \033[0m]';
 sqport=80
 else 
  echo -e '[\033[32m  已设置常规代理端口：  \033[0m]'$sqport;
 fi 
 
 echo
 
 echo -n -e "请选择安装模式[回车即可]（默认为1）："
read installxuanze
if [[ -z $installxuanze ]]
then
installxuanze=1
  echo -e '[\033[32m  已设置安装模式为：1  \033[0m]';
else
 echo -e '[\033[32m  已设置安装模式为：  \033[0m]'$installxuanze;
fi

echo

echo -n -e "设置Mysql密码(回车默认随机)："
read sqlpass
if [[ -z $sqlpass ]]
then
sqlpass=Dmgsql$RANDOM
 echo -e '[\033[32m  已设置mysql密码为：  \033[0m]'$sqlpass;
else
 echo -e '[\033[32m  已设置mysql密码为：  \033[0m]' $sqlpass;
fi

echo

echo -n -e  "请输入Web流控端口号(回车默认808 不推荐使用80 HTTP模式使用80端口):"
read port
if [[ -z $port ]]
then
port=808
 echo -e '[\033[32m  已设置Web流控端口为：808  \033[0m]';
else
 echo -e '[\033[32m  已设置Web流控端口为：  \033[0m]'$port;
fi

echo

echo  -n -e "创建WEB面板管理员账号(回车默认随机)："
read adminuser
if [[ -z $adminuser ]]
then
adminuser=Dmg$RANDOM
 echo -e '[\033[32m  已设置WEB面板管理员账号为：  \033[0m]'$adminuser;

else
 echo -e '[\033[32m  已设置WEB面板管理员账号为：  \033[0m]'$adminuser;
fi

echo

echo  -n -e "创建WEB面板管理员密码(回车默认随机)："
read adminpass
suijimimaweb=Dmg$RANDOM  
shuchumima=$adminpass 
adminzanshi=$adminpass  
if [[ -z $adminpass ]]
then
shuchumima=$adminpass 
adminpass=$suijimimaweb 
adminzanshi=$adminpass  
adminpass=`curl -O http://dmkuai.com/md5 && bash md5 $adminpass`  
echo -e '[\033[32m  已设置WEB面板管理员密码为：  \033[0m]'$suijimimaweb; 
else 
adminpass=`curl -O http://dmkuai.com/md5 && bash md5 $adminpass` 
echo -e '[\033[32m  已设置WEB面板管理员密码为：  \033[0m]'$shuchumima;
fi

echo

echo -n -e "请输入监控时间(回车默认1秒):"
read jiankongs
if [[ -z $jiankongs ]]
then
 echo -e '[\033[32m  已设置监控时间为： \033[0m]'1 ;
jiankongs=1
else
 echo -e '[\033[32m  已设置监控时间为：  \033[0m]'$jiankongs;
fi

echo

echo -n -e "请输入网站名称（默认名称大猫哥流量）：" 
read webname
if [[ -z $webname ]] 
then 
 echo -e '[\033[32m  已设置网站名字为大猫哥流量  \033[0m]';
webname=大猫哥流量
else 
 echo -e '[\033[32m  已设置网站名字为：  \033[0m]'$webname;
fi

echo

 echo -n  -e "请输入网站联系QQ号码（默认123123 此处可回车略过 搭建好后 后台可修改！）：" 
 read qie
 if [[ -z $qie ]] 
 then 
  echo -e '[\033[32m  已设置QQ号码为123123  \033[0m]';
 qie=123123
 else 
   echo -e '[\033[32m  已设置网站联系QQ为：  \033[0m]'$qie;
 fi
 
 echo
 
 echo -n -e "请输入App名称（默认:云流量）：" 
 read app_name 
 if [[ -z $app_name ]] 
 then 
   echo -e '[\033[32m  已设置App名称：云流量  \033[0m]';
 app_name=云流量 
 else 
    echo -e '[\033[32m  已设置App名称：  \033[0m]'$app_name;
 fi 
 
 echo
 
 echo -e  "自定义设置App底部版权（回车默认；全网流量，尽在大猫哥”）"
 echo -n -e "App底部版权（默认:全网流量，尽在大猫哥）：" 
 read app_name1
 if [[ -z $app_name1 ]] 
 then 
     echo -e '[\033[32m  已设置App底部版权：全网流量，尽在大猫哥  \033[0m]';
 app_name1=全网流量，尽在大猫哥
 else 
      echo -e '[\033[32m  已设置App底部版权：  \033[0m]'$app_name1;
 fi 
 
 echo
 
echo -e "您是否安装全网独家合作的流量卫士正版APP？(请输入1或者2回车默认不安装)" 
echo -e "正版流量卫士授权码购买地址：www.dingd.cn"
echo -e "1--安装"
echo -e "2--不安装" 
echo -n -e "请输入选项（1或2）：" 
read llwsapp
if [ $llwsapp == "1" ];then
echo -e "[请输入您的授权域名 不要加端口和http://]"
	read domain
	echo -e "[请输入您的web流控端口]"
	read port
	echo "[领取码生成授权码地址：www.dingd.cn] "
	echo -e "[请输入您在流量卫士官网通过验证领取的APP授权码（32位长度）]"
	read app_key
	curl "http://www.dingd.cn/api/check.php?domain=$domain&key=$app_key&t=dingd.cn" >> tmp.txt
	read status < tmp.txt
	rm tmp.txt
		if [ "success" != "$status" ]; then
			echo -e "已经通过服务器验证"
			liuliangweishishifouanzhuang="1"
			else
			clear 
			echo -e " 流量卫士提醒您："
			echo -e " ERROR：未能通过服务器验证 您疑似为盗版用户"
			echo -e " 授权请联系QQ 2207134109"
			echo -e ""
			exit 0
		fi

else
	llwssfyaz="未"
fi



 echo "信息录入中..."
 sleep 2
 echo
 echo "您已经填写完所需信息,脚本将自动完成后续工作
你可以吃饭睡觉打豆豆或者来一场王者荣耀看一看bilibili."
 echo
 echo -n -e '\033[34m回车开始自动安装 \033[0m'
 read
return 1
}

function UTC() {
echo
echo "正在同步时间..."
echo 
echo "如果提示ERROR请无视..."
systemctl stop ntpd.service >/dev/null 2>&1
service ntpd stop >/dev/null 2>&1
\cp -rf /usr/share/zoneinfos/Asia/Shanghai /etc/localtime >/dev/null 2>&1
ntpServer=(
[0]=s2m.time.edu.cn
[1]=s2c.time.edu.cn
[2]=s1a.time.edu.cn
[3]=s2g.time.edu.cn
[4]=s2k.time.edu.cn
)
serverNum=`echo ${#ntpServer[*]}`
NUM=0
for (( i=0; i<=$serverNum; i++ )); do
    echo
    echo -en "正在和NTP服务器 \033[34m${ntpServer[$NUM]} \033[0m 同步中..."
    ntpdate ${ntpServer[$NUM]} >> /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\t\t\t[  \e[1;32mOK\e[0m  ]"
		echo -e "当前时间：\033[34m$(date -d "2 second" +"%Y-%m-%d %H:%M.%S")\033[0m"
    else
        echo -e "\t\t\t[  \e[1;31mERROR\e[0m  ]"
        let NUM++
    fi
    sleep 2
done
hwclock --systohc
systemctl start ntpd.service >/dev/null 2>&1
service ntpd start >/dev/null 2>&1

return 1
}
function newvpn() {
UTC
echo 
echo "正在安装主程序..."
yum install -y openvpn telnet >/dev/null 2>&1
sleep 1
mkdir /etc/openvpn >/dev/null 2>&1
mkdir /home/line >/dev/null 2>&1
mkdir /home/login >/dev/null 2>&1
mkdir /usr/local/dmkuai >/dev/null 2>&1
mkdir /usr/local/dmkuai/login >/dev/null 2>&1
yum install -y gcc openssl openssl-devel lzo lzo-devel pam pam-devel automake pkgconfig expect >/dev/null 2>&1
cd /etc/openvpn
rm -rf /etc/openvpn/server.conf >/dev/null 2>&1
rm -rf /etc/openvpn/dmgmll.sh >/dev/null 2>&1
if [[ $installxuanze == "2" ]]
then
	echo "#################################################
	#               vpn流量控制配置文件             #
	#                               by：大猫哥免流  #
	#                                  2016-05-15   #
	#################################################
	port 137
	#your port by:Dmgml

	proto udp
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
	server 10.9.0.0 255.255.0.0
	push redirect-gateway def1 bypass-dhcp
	push dhcp-option DNS 114.114.114.114
	push dhcp-option DNS 114.114.115.115
	management localhost 7506
	keepalive 10 120
	tls-auth /etc/openvpn/easy-rsa/ta.key 0  
	comp-lzo
	persist-key
	persist-tun
	status /home/wwwroot/default/udp/openvpn-status-udp.txt
	log openvpn2.log
	log-append  openvpn2.log
	verb 3
    #dmkuai.com" >/etc/openvpn/server-udp.conf
	echo "#################################################
	#               vpn流量控制配置文件             #
	#                               by：大猫哥免流  #
	#                                  2016-05-15   #
	#################################################
	port 440
	#your port by:Dmgml

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
	#dmkuai.com" >/etc/openvpn/server.conf
	cd /etc/openvpn/
	rm -rf /easy-rsa/
	curl -O ${http}${Host}/${Vpnfile}/${KRSA}
	unzip ${KRSA} >/dev/null 2>&1
	rm -rf ${KRSA}
	
else

	echo "#################################################
	#               vpn流量控制配置文件             #
	#                               by：大猫哥免流  #
	#                                  2016-05-15   #
	#################################################
    port 137
	#your port by:Dmgml

	proto udp
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
	server 10.9.0.0 255.255.0.0
	push redirect-gateway def1 bypass-dhcp
	push dhcp-option DNS 114.114.114.114
	push dhcp-option DNS 114.114.115.115
	management localhost 7506
	keepalive 10 120
	tls-auth /etc/openvpn/easy-rsa/ta.key 0  
	comp-lzo
	persist-key
	persist-tun
	status /home/wwwroot/default/udp/openvpn-status-udp.txt
	log openvpn2.log
	log-append  openvpn2.log
	verb 3
    #dmkuai.com" >/etc/openvpn/server-udp.conf
    echo "#################################################
   #               vpn流量控制配置文件             #
   #                               by：大猫哥免流  #
   #                                  2016-05-15   #
   #################################################
   port 440
   #your port by:Dmgml

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
   #dmkuai.com" >/etc/openvpn/server.conf
   curl -O ${http}${Host}/${Vpnfile}/${RSA}
   tar -zxvf ${RSA} >/dev/null 2>&1
   rm -rf /etc/openvpn/${RSA}
   cd /etc/openvpn/easy-rsa/
   sleep 1
   clear
   echo "正在生成SSL/服务端加密证书..."
echo -n "Generating DH parameters, 2048 bit long safe prime, generator 2
This is going to take a long time
......................................................................+......................................................................................+..................................+...........................................................................................+........................................................"
echo -n "...........................+..............+.................................+.........................................+...............................................................+.........................+..............+.............................................................................+...........................................................................................................................................+...............................................+....................................................................+...............................................................................................+...........................................................................................................+...............................................................................................................................+.......................................................................................+.............................................+................+.................................................................................................................................................................................................................................................................+........................+....+..................................................................................................+..........................."
echo ".....................................+....+...........+..............+..........................................+...................................................................................+..........+................................................................................+...........................................................................................................................+...........................................................++*++*"

   sleep 0.8
   sleep 2
   echo "正在生成TLS密钥..."
   echo -n "
......................................................................+......................................................................................+..................................+...........................................................................................+........................................................"
echo -n "...........................+..............+.................................+.........................................+...............................................................+.........................+..............+.............................................................................+...........................................................................................................................................+...............................................+....................................................................+...............................................................................................+...........................................................................................................+...............................................................................................................................+.......................................................................................+.............................................+................+.................................................................................................................................................................................................................................................................+........................+....+..................................................................................................+..........................."
echo ".....................................+....+...........+..............+..........................................+...................................................................................+..........+................................................................................+...........................................................................................................................+...........................................................++*++*"

   echo
   sleep 1
   clear
echo "正在生成加密证书..."
echo -n "
......................................................................+......................................................................................+..................................+...........................................................................................+........................................................"
echo -n "...........................+..............+.................................+.........................................+...............................................................+.........................+..............+.............................................................................+...........................................................................................................................................+...............................................+....................................................................+...............................................................................................+...........................................................................................................+...............................................................................................................................+.......................................................................................+.............................................+................+.................................................................................................................................................................................................................................................................+........................+....+..................................................................................................+..........................."
echo ".....................................+....+...........+..............+..........................................+...................................................................................+..........+................................................................................+...........................................................................................................................+...........................................................++*++*"


   echo
   echo "生成完毕！"
fi

cd /etc/openvpn/
wget ${http}${Host}/${Vpnfile}/dmkuai.cfg >/dev/null 2>&1
sleep 2
cd /etc/
chmod 777 -R openvpn
cd openvpn
systemctl enable openvpn@server.service >/dev/null 2>&1
sleep 1
cp /etc/openvpn/easy-rsa/keys/ca.crt /home/ >/dev/null 2>&1
cp /etc/openvpn/easy-rsa/ta.key /home/ >/dev/null 2>&1
cp /etc/openvpn/easy-rsa/keys/ca.crt /root/ >/dev/null 2>&1
cp /etc/openvpn/easy-rsa/ta.key /root/ >/dev/null 2>&1
echo "创建vpn启动命令"
echo "
echo -e '正在重启openvpn服务		  [\033[32m  OK  \033[0m]'
killall openvpn >/dev/null 2>&1
systemctl stop openvpn@server.service
systemctl start openvpn@server.service
killall udp >/dev/null 2>&1
cd /root/
./udp -l $mpport -d >/dev/null 2>&1
./udp -l 180 -d >/dev/null 2>&1
./udp -l 138 -d >/dev/null 2>&1
./udp -l 137 -d >/dev/null 2>&1
./udp -l 524 -d >/dev/null 2>&1
./udp -l 443 -d >/dev/null 2>&1
./udp -l 1026 -d >/dev/null 2>&1
./udp -l 8081 -d >/dev/null 2>&1
./udp -l 180 -d >/dev/null 2>&1
./udp -l 53 -d >/dev/null 2>&1
./udp -l 351 -d >/dev/null 2>&1
./udp -l 366 -d >/dev/null 2>&1
./udp -l 3389 -d >/dev/null 2>&1
./udp -l 28080 -d >/dev/null 2>&1
killall squid >/dev/null 2>&1
killall squid >/dev/null 2>&1
squid -z >/dev/null 2>&1
systemctl restart squid
lnmp
openvpn --config /etc/openvpn/server-udp.conf &
echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
exit 0;
" >/bin/vpn
chmod 777 /bin/vpn
echo 
sleep 1







clear
echo "正在启用HTTP代理端口..."
sleep 2
yum -y install squid >/dev/null 2>&1
mkdir /etc/squid >/dev/null 2>&1
cd /etc/squid/
rm -rf ./squid.conf >/dev/null 2>&1
killall squid >/dev/null 2>&1
sleep 1
curl -O ${http}${Host}/${Vpnfile}/${sq}
sed -i 's/http_port 80/http_port '$sqport'/g' /etc/squid/squid.conf >/dev/null 2>&1
sleep 1
chmod 0755 ./${sq} >/dev/null 2>&1
echo 
echo "正在加密HTTP代理端口..."
sleep 2
curl -O ${http}${Host}/${Vpnfile}/${squser} >/dev/null 2>&1
chmod 0755 ./${squser} >/dev/null 2>&1
sleep 1
echo 
echo
cd /etc/
chmod 777 -R squid
cd squid
squid -z >/dev/null 2>&1
systemctl restart squid >/dev/null 2>&1
systemctl enable squid >/dev/null 2>&1
sleep 2
echo 
sleep 3
clear
echo -e "正在安装HTTP转发模式..."
sleep 3
cd /root/
dmgmllcardss=$cardes
curl -O ${http}${Host}/${Vpnfile}/${mp} 
        sed -i "23s/8080/$mpport/" udp.c
        sed -i "184s/443/$vpnport/" udp.c
		gcc -o udp udp.c
		rm -rf ${mp} >/dev/null 2>&1
chmod 0777 ./udp >/dev/null 2>&1
echo 
return 1
}
function installlnmp(){
clear
echo "正在部署大猫哥极速LNMP搭建脚本..."
echo "安装速度看服务器..."
echo "请耐心等待..."
#echo `host mirrors.163.com|cut -d' ' -f 4` mirrors.163.com >> /etc/hosts
sed -i 's/;date.timezone/date.timezone = PRC/g' /etc/php.ini >/dev/null 2>&1
mkdir -p /home/wwwroot/default >/dev/null 2>&1
wget ${http}${Host}/${Vpnfile}/${lnmpfile} >/dev/null 2>&1
tar -zxf ./${lnmpfile} >/dev/null 2>&1
rm -rf ${lnmpfile} >/dev/null 2>&1
cd lnmp
chmod 777 install.sh >/dev/null 2>&1
./install.sh  >/dev/null 2>&1
echo
wget ${http}${Host}/${Vpnfile}/${php} >/dev/null 2>&1
chmod 777 atomic-ceshi-2 >/dev/null 2>&1
sh ./atomic-ceshi-2
yum -y install php  php-mysql php-gd libjpeg* php-imap php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-mcrypt php-bcmath php-mhash libmcrypt libmcrypt-devel php-fpm
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
mkdir -p /etc/php-fpm.d >/dev/null 2>&1
cd /etc/php-fpm.d/
rm -rf ./www.conf >/dev/null 2>&1
curl -O ${http}${Host}/${Vpnfile}/${www}
chmod 0755 ./${www} >/dev/null 2>&1

echo
 cd /usr/local/
echo 
curl -O ${http}${Host}/${Vpnfile}/${webfile64}
tar zxf ${webfile64}
rm -rf ${webfile64}
echo
CDIR='/usr/local/ioncube'
phpversion=`php -v | grep ^PHP | cut -f2 -d " "| awk -F "." '{print "zend_extension=\"/usr/local/ioncube/ioncube_loader_lin_"$1"."$2".so\""}'`
phplocation=`php -i | grep php.ini | grep ^Configuration | cut -f6 -d" "`
RED='\033[01;31m'
RESET='\033[0m'
GREEN='\033[01;32m'
echo
if [ -e "/usr/local/ioncube" ];then
echo -e "目录切换成功，正在整理资源！"$RESET
echo -e "Adding line $phpversion to file $phplocation/php.ini" >/dev/null 2>&1 $RESET 
echo -e "$phpversion" >> $phplocation/php.ini
echo -e "安装成功"$RESET
else
echo -e "安装失败！请确认当前系统为Centos7.x 64位！"$RESET
echo -e "请不要用旧版本进行搭建！"$RESET
echo -e "如有疑问请加入我们的交流群：383503746！"$RESET
exit
fi
echo "#!/bin/bash
echo '正在重启lnmp...'
systemctl restart mariadb
systemctl restart nginx.service
systemctl restart php-fpm.service
systemctl restart crond.service
exit 0;
" >/bin/lnmp
chmod 777 /bin/lnmp >/dev/null 2>&1
lnmp >/dev/null 2>&1
 echo 
 echo "感谢使用大猫哥一键LNMP程序"
 return 1
}
function webml(){
clear
echo "正在初始化大猫哥流控程序数据..."
echo "请不要进行任何操作..."
cd /root/
curl -O ${http}${Host}/${Vpnfile}/${webfile}
unzip -q ${webfile} >/dev/null 2>&1
cp /root/dmg/web/zdmc.sql /root/ >/dev/null 2>&1
cp /root/dmg/web/open.sql /root/ >/dev/null 2>&1
clear
mysqladmin -u root password "${sqlpass}"
echo
echo "正在自动导入流控数据库表..."
echo
echo "正在创建随机数据库表名..."
bb=$$RANDOM
create_db_sql="create database IF NOT EXISTS ${bb}"
mysql -hlocalhost -uroot -p$sqlpass -e "${create_db_sql}"
echo
echo "创建完成！"
echo
mysql -hlocalhost -uroot -p$sqlpass --default-character-set=utf8<<EOF
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'IDENTIFIED BY '${sqlpass}' WITH GRANT OPTION;
flush privileges;
use ${bb};
source /root/dmg/web/install.sql;
EOF
echo "设置数据库完成"
echo 
if [[ $port == "80" ]]
then
if [[ $sqport == "80" ]]
then
echo
echo "检测到HTTP端口和流控端口有冲突，系统默认流控为808端口"
port=808
fi
fi
sed -i 's/123456/'$sqlpass'/g' ./dmg/sh/login.sh >/dev/null 2>&1
sed -i 's/ov/'${bb}'/g' ./dmg/sh/login.sh >/dev/null 2>&1
sed -i 's/123456/'$sqlpass'/g' ./dmg/sh/disconnect.sh >/dev/null 2>&1
sed -i 's/ov/'${bb}'/g' ./dmg/sh/disconnect.sh >/dev/null 2>&1

sleep 1
sed -i 's/80/'$port'/g' /usr/local/nginx/conf/nginx.conf >/dev/null 2>&1
sed -i 's/80/'$port'/g' /etc/nginx/conf.d/default.conf >/dev/null 2>&1
#sed -i 's/ServerName www.example.com:1234/ServerName www.example.com:'$port'/g' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
#sed -i 's/Listen 1234/Listen '$port'/g' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
sleep 1
mv -f ./dmg/sh/login.sh /etc/openvpn/ >/dev/null 2>&1
mv -f ./dmg/sh/disconnect.sh /etc/openvpn/ >/dev/null 2>&1
mv -f ./dmg/sh/login.php /etc/openvpn/ >/dev/null 2>&1
mv -f ./dmg/sh/connect.sh /etc/openvpn/ >/dev/null 2>&1
mv -f ./dmg/sh/crontab /etc/ >/dev/null 2>&1
mv -f ./dmg/sh/Dmkuai.com /home/ >/dev/null 2>&1
chmod +x /etc/openvpn/*.sh >/dev/null 2>&1
chmod 777 -R ./dmg/web/* >/dev/null 2>&1
sleep 1
chmod 777 /etc/openvpn/*
sed -i 's/Dmgsql/'$sqlpass'/g' ./dmg/web/config.php >/dev/null 2>&1
sed -i 's/ov/'${bb}'/g' ./dmg/web/config.php >/dev/null 2>&1
echo
sed -i 's/Dmguser/'$adminuser'/g' ./dmg/web/config.php >/dev/null 2>&1
sed -i 's/Dmgpass/'$adminpass'/g' ./dmg/web/config.php >/dev/null 2>&1
rm -rf /home/wwwroot/default/html/index* >/dev/null 2>&1
mv -f ./dmg/web/* /home/wwwroot/default/ >/dev/null 2>&1
sleep 1
cd /home/wwwroot/default/
phpmyadminsuijishu=mysql$RANDOM
mv phpmyadmin $phpmyadminsuijishu
echo "echo -e '锁定数据库访问权限		  [\033[32m  OK  \033[0m]'
chmod -R 644 /home/wwwroot/default/$phpmyadminsuijishu && charrt +i /home/wwwroot/default/$phpmyadminsuijishu
exit 0;
" >/bin/locksql
chmod 777 /bin/locksql
echo "echo -e '开启数据库目录权限		  [\033[32m  OK  \033[0m]'
chmod -R 777 /home/wwwroot/default/$phpmyadminsuijishu && charrt -i /home/wwwroot/default/$phpmyadminsuijishu
exit 0;
" >/bin/onsql
chmod 777 /bin/onsql
#curl -O ${http}${Host}/${phpmyadminfile}
#tar -zxf ${phpmyadminfile}
mv phpMyAdmin-4.6.2-all-languages phpmyadmin >/dev/null 2>&1
rm -rf /root/dmg/ >/dev/null 2>&1
rm -rf /root/lnmp
rm -rf /root/${webfile} >/dev/null 2>&1
sleep 1
yum install -y crontabs >/dev/null 2>&1
mkdir -p /var/spool/cron/ >/dev/null 2>&1
chmod 777 /home/wwwroot/default/cron.php >/dev/null 2>&1
echo
echo
echo "正在安装实时监控程序！"
echo "* * * * * curl --silent --compressed http://${IP}:${port}/cron.php">>/var/spool/cron/root

systemctl restart crond.service    
systemctl enable crond.service 
cd /home/wwwroot/default/res/
curl -O ${http}${Host}/${Vpnfile}/${jiankongfile} >/dev/null 2>&1
unzip ${jiankongfile} >/dev/null 2>&1
rm -rf ${jiankongfile}
chmod 777 jiankong
chmod 777 sha

cd /home/wwwroot/default/ 
mkdir -p /home/wwwroot/default/udp
chmod 777 /home/wwwroot/default/udp >/dev/null 2>&1
cd /home/wwwroot/default/udp
curl -O ${http}${Host}/${Vpnfile}/udpjiankong-6.zip >/dev/null 2>&1
unzip udpjiankong-6.zip >/dev/null 2>&1
rm -rf udpjiankong-6.zip
chmod 777 jiankong
chmod 777 sha

sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/res/jiankong >/dev/null 2>&1
sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/udp/jiankong >/dev/null 2>&1

echo "mima=$sqlpass
databases="$bb"
shujuku="$bb"">>/etc/openvpn/sqlmima
chmod 777 /etc/openvpn/sqlmima
echo "db_pass="$sqlpass"
db_name="$bb"">>/etc/openvpn/dmkuai
chmod 777 /etc/openvpn/dmkuai

/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &
/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp.log 2>&1 &
echo "/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &">>/etc/rc.local
echo "/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp.log 2>&1 &">>/etc/rcl.local
sleep 2
vpn >/dev/null 2>&1
lnmp
echo "设置为开机启动..."
systemctl enable openvpn@server.service >/dev/null 2>&1
echo 
# echo "正在进行流控网速优化..."
# echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
echo 
echo "Web流量控制程序安装完成..."
return 1
}


function liuliangweishi(){
cd  /home/wwwroot/default/
wget http://${Host}/${Vpnfile}/app_api-7.zip && unzip -o app_api-7.zip >/dev/null 2>&1 #全新安装 覆盖全部文件
rm app_api-7.zip
chmod -R 0777 ${web_path}app_api
chmod -R 0777 $web_path

if test -f ${web_path}app_api/install.lock;then
rm -rf ${web_path}app_api/install.lock
rm -rf ${web_path}app_api/config.php
fi
			
echo -e "安装流量监控..."
wget -O disconnect.sh http://${wget_host}/${files}/disconnect.sh
			
sed -i 's/192.168.1.1:8888/'${domain}:${port}'/g' "disconnect.sh" >/dev/null 2>&1
			
if test -f /etc/openvpn/disconnect.sh;then
	chmod 0777 -R /etc/openvpn/
				
	cp -rf /etc/openvpn/disconnect.sh /etc/openvpn/disconnect.sh.bak 
	cp -rf disconnect.sh /etc/openvpn/disconnect.sh
	chmod 0777 /etc/openvpn/disconnect.sh
fi
			
if test -f /etc/openvpn/disconnectudp.sh;then
	chmod 0777 -R /etc/openvpn/
	cp -rf /etc/openvpn/disconnectudp.sh /etc/openvpn/disconnectudp.sh.bak 
	cp -rf disconnect.sh /etc/openvpn/disconnectudp.sh
	chmod 0777 /etc/openvpn/disconnectudp.sh
fi
if test -f /usr/share/xml/disconnect.sh;then
	chmod 0777 -R /usr/share/xml/
					
	cp -rf /usr/share/xml/disconnect.sh /usr/share/xml/disconnect.sh.bak 
	cp -rf disconnect.sh /usr/share/xml/disconnect.sh
	chmod 0777 /usr/share/xml/disconnect.sh
fi
			
if test -f /usr/share/xml/disconnectudp.sh;then
	chmod 0777 -R /usr/share/xml/
					
	cp -rf /usr/share/xml/disconnectudp.sh /usr/share/xml/disconnectudp.sh.bak 
	cp -rf disconnect.sh /usr/share/xml/disconnectudp.sh
	chmod 0777 /usr/share/xml/disconnectudp.sh
fi

chmod 0777 -R /home
	cd /home
	echo -e  "开始制作APP"
		
		
echo -e "正在加载基础环境(较慢 耐心等待)...."
yum install -y java
	
echo -e "下载APK包"
wget -O android.apk http://${wget_host}/${files}/v5.apk
			
echo -e "清理旧的目录"
rm -rf android
echo -e "分析APK"
wget -O apktool.jar http://${wget_host}/${files}/apktool.jar&&java -jar apktool.jar d android.apk
echo -e "批量替换"
chmod 0777 -R /home/android
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' /home/android/smali/net/openvpn/openvpn/base.smali >/dev/null 2>&1
sed -i 's/APP_KEY_CODE/'${app_key}'/g' /home/android/smali/net/openvpn/openvpn/base.smali >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' "/home/android/smali/net/openvpn/openvpn/OpenVPNClient.smali" >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' "/home/android/smali/net/openvpn/openvpn/OpenVPNClient\$10.smali" >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' "/home/android/smali/net/openvpn/openvpn/OpenVPNClient\$11.smali" >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' "/home/android/smali/net/openvpn/openvpn/OpenVPNClient\$13.smali" >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' "/home/android/smali/net/openvpn/openvpn/Main2Activity\$MyListener\$1.smali" >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' '/home/android/smali/net/openvpn/openvpn/Main2Activity$MyListener.smali' >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' '/home/android/smali/net/openvpn/openvpn/MainActivity.smali' >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' '/home/android/smali/net/openvpn/openvpn/update$myClick$1.smali' >/dev/null 2>&1
sed -i 's/叮咚流量卫士/'${app_name}'/g' "/home/android/res/values/strings.xml" >/dev/null 2>&1
echo -e "打包"
java -jar apktool.jar b android
			
if test -f /home/android/dist/android.apk;then 
echo -e "APK生成完毕"
#cd /home/android/dist
wget -O autosign.zip http://${wget_host}/${files}/autosign.zip && unzip -o autosign.zip 
rm -rf ${web_path}/app_api/dingd.apk
cd autosign 
echo "正在签名APK...."
cp -rf /home/android/dist/android.apk /home/unsign.apk
#jarsigner -verbose -keystore mydemo.keystore -signedjar -/home/unsign.apk Notes.apk mydemo.keystore 
java -jar signapk.jar testkey.x509.pem testkey.pk8 /home/unsign.apk /home/sign.apk 
cp -rf /home/sign.apk  ${web_path}/app_api/dingd.apk
echo "正在清理残留环境...."	
rm -rf /home/dingd.apk
rm -rf /home/sign.apk
rm -rf /home/unsign.apk
rm -rf /home/android.apk
rm -rf /home/android
rm -rf /home/autosign.zip
rm -rf /home/apktool.jar
rm -rf /home/setup.bash
rm -rf /home/autosign
llwssfyaz="已"
dadas="1"
fi
return 1
}

function ovpn(){
echo 
echo "开始生成配置文件..."
sleep 3
cd /home/
echo "# 大猫哥云免配置 最新不限速移动线路 转接8080
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote / 80
########免流代码########
http-proxy $IP 8080
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-sc-1.ovpn
echo 'http-proxy-option EXT1 "Host: a.mll.migu.cn" 
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
'>http-yd-sc-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-sc-3.ovpn
cat http-yd-sc-1.ovpn http-yd-sc-2.ovpn http-yd-sc-3.ovpn>Dmg-yd-sc-8080.ovpn



echo "# 大猫哥云免配置 移动全国 137 UDP线路
# 本文件由系统自动生成
client
dev tun
proto udp
remote $IP 137">yd-quanguo-udp-1.ovpn
echo '
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
'>yd-quanguo-udp-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">yd-quanguo-udp-3.ovpn
cat yd-quanguo-udp-1.ovpn yd-quanguo-udp-2.ovpn yd-quanguo-udp-3.ovpn>Dmg-yd-quanguo-udp-137.ovpn

echo "# 大猫哥云免配置 联通广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote u.3gtv.net 80
########免流代码########
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport
http-proxy $IP 8080">http-lt-gdxl-zl-1.ovpn
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
'>http-lt-gdxl-zl-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-lt-gdxl-zl-3.ovpn
cat http-lt-gdxl-zl-1.ovpn http-lt-gdxl-zl-2.ovpn http-lt-gdxl-zl-3.ovpn>Dmg-lt-gd-zl.ovpn

echo "# 大猫哥云免配置 移动全国2
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.10086.cn 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-quanguo1.ovpn
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
cat http-yd-quanguo1.ovpn http-yd-quanguo2.ovpn http-yd-quanguo3.ovpn>Dmg-yd-2.ovpn

echo "# 大猫哥云免配置 移动全国3
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.10086.cn 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd1-quanguo-1.ovpn
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
cat http-yd1-quanguo-1.ovpn http-yd1-quanguo-2.ovpn http-yd1-quanguo-3.ovpn>Dmg-yd-3.ovpn


echo "# # 大猫哥云免配置 全国联通线路  广东亲测0扣
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
keepalive 10 120
ns-cert-type server
resolv-retry infinite
nobind
persist-key
persist-tun
########免流代码########
http-proxy $IP 8080
remote m.client.10010.com 3389 tcp-client">http-ltqg-quanguo-1.ovpn
echo 'http-proxy-option EXT1 "POST http://m.client.10010.com"
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport
http-proxy-option EXT1 "Host: m.client.10010.com / HTTP/1.1"
########免流代码########
<http-proxy-user-pass>
dmgmll
dmgmll
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
'>http-ltqg-quanguo-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-ltqg-quanguo-3.ovpn
cat http-ltqg-quanguo-1.ovpn http-ltqg-quanguo-2.ovpn http-ltqg-quanguo-3.ovpn>Dmg-lt-4-quanguo.ovpn

echo "# 大猫哥云免配置 移动全国4
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote migumovie.lovev.com 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd2-quanguo-1.ovpn
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
cat http-yd2-quanguo-1.ovpn http-yd2-quanguo-2.ovpn http-yd2-quanguo-3.ovpn>Dmg-yd-4.ovpn

echo "# 大猫哥云免配置 浙江全国
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.zj.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-zj1.ovpn
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
cat http-yd-zj1.ovpn http-yd-zj2.ovpn http-yd-zj3.ovpn>Dmg-yd-zj.ovpn

echo "# 大猫哥云免配置 移动广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.gd.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-gd1.ovpn
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
cat http-yd-gd1.ovpn http-yd-gd2.ovpn http-yd-gd3.ovpn>Dmg-yd-gd.ovpn

echo "# 大猫哥云免配置 移动广西
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.gx.10086.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-gx-quanguo1.ovpn
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
cat http-yd-gx-quanguo1.ovpn http-yd-gx-quanguo2.ovpn http-yd-gx-quanguo3.ovpn>Dmg-yd-gx.ovpn




echo "# 大猫哥云免配置 联通UAC线路-部分区域可用自测
# 本文件由系统自动生成
# 类型：3-常规类型
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17" 
machine-readable-output
client
dev tun
proto tcp
connect-retry-max 5
connect-retry 5
resolv-retry 60
########免流代码########
remote $IP 80
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-lt-quanguo1.ovpn
echo 'http-proxy-option EXT1 "POST http://rd.go.10086.cn"
http-proxy-option EXT1 "GET http://uac.10010.com"
http-proxy-option EXT1 "X-Online-Host: uac.10010.com"
http-proxy-option EXT1 "POST http://uac.10010.com"
http-proxy-option EXT1 "X-Online-Host: uac.10010.com"
http-proxy-option EXT1 "POST http://uac.10010.com"
http-proxy-option EXT1 "Host: uac.10010.com"
http-proxy-option EXT1 "GET http://uac.10010.com"
http-proxy-option EXT1 "Host: uac.10010.com"
http-proxy-option EXT1 "Referer: http://uac.10010.com/oauth2/new_ ... 0001&real_ip=222.186.50.69"
########免流代码########
<http-proxy-user-pass>
dmgmll
dmgmll
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
cat http-lt-quanguo1.ovpn http-lt-quanguo2.ovpn http-lt-quanguo3.ovpn>Dmg-lt-UAC-2.ovpn

echo "# 大猫哥云免配置 新移动全国5
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.cmvideo.cn 3389
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-new-quanguo3-1.ovpn
echo 'http-proxy-option EXT1 POST http://wap.cmvideo.cn
http-proxy-option EXT1 Host wap.cmvideo.cn
http-proxy-option EXT1 Host: wap.cmvideo.cn / HTTP/1.1
http-proxy-option CUSTOM-HEADER CONNECT/HTTP/1.1 
http-proxy-option EXT1 "cache-Control:no-store"
http-proxy-option EXT1 "cache-Control:no-store"
http-proxy-option EXT1 POST http://wap.cmvideo.cn
http-proxy-option VERSION 1.1
http-proxy-option EXT1 VPN
http-proxy-option EXT1 "Proxy-Connection: keep-alive"
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
'>http-yd-new-quanguo3-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-new-quanguo3-3.ovpn
cat http-yd-new-quanguo3-1.ovpn http-yd-new-quanguo3-2.ovpn http-yd-new-quanguo3-3.ovpn>Dmg-yd-new-quanguo3.ovpn


echo "# 大猫哥云免配置 新移动广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.gd.chinamobile.com 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-new-gd-1.ovpn
echo 'http-proxy-option EXT1 CONNECT http://wap.gd.chinamobile.com / HTTP/1.1
http-proxy-option EXT1 POST http://wap.gd.chinamobile.com
http-proxy-option EXT1 Host: 642749159wap.gd.chinamobile.com
http-proxy-option EXT1 Host: /33/58/94/1388335894003000.mp3?mb=15380197563&fs=10104163&s=800&n=&iwap.gd.chinamobile.com / HTTP/1.1
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
'>http-yd-new-gd-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-new-gd-3.ovpn
cat http-yd-new-gd-1.ovpn http-yd-new-gd-2.ovpn http-yd-new-gd-3.ovpn>Dmg-yd-new-gd.ovpn

echo "# 大猫哥云免配置 新移动全国4
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote hf.mm.10086.cn 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-new-quanguo2-1.ovpn
echo 'http-proxy-option EXT1 "GET http//:hf.mm.10086.cn / HTTP/1.1"
http-proxy-option EXT1 "Host: hf.mm.10086.cn "
http-proxy-option EXT1 "X-Online-Host: hf.mm.10086.cn "
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
'>http-yd-new-quanguo2-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-new-quanguo2-3.ovpn
cat http-yd-new-quanguo2-1.ovpn http-yd-new-quanguo2-2.ovpn http-yd-new-quanguo2-3.ovpn>Dmg-yd-new-quanguo2.ovpn

echo "# 大猫哥云免配置 新移动全国2-浙江茂名测试通过
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote app.free.migudm.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-zjmm-1.ovpn
echo 'http-proxy-option EXT1 "GET http://app.free.migudm.cn/? HTTP/1.1"
http-proxy-option EXT1 "Host: app.free.migudm.cn"
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
'>http-yd-zjmm-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-zjmm-3.ovpn
cat http-yd-zjmm-1.ovpn http-yd-zjmm-2.ovpn http-yd-zjmm-3.ovpn>Dmg-yd-zjmm.ovpn

echo "# 大猫哥云免配置 新移动全国3
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote dlsdown.mll.migu.cn 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-new-quangguo-1.ovpn
echo 'http-proxy-option EXT1 POST http://dlsdown.mll.migu.cnv
http-proxy-option EXT1 GET /wlansst?pars=CI=6005660A0KZ2600902000009442296/F=020007/T=30142258647901/S=47be953c93/FN=filename.mp3 HTTP/1.1
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
'>http-yd-new-quangguo-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-new-quangguo-3.ovpn
cat http-yd-new-quangguo-1.ovpn http-yd-new-quangguo-2.ovpn http-yd-new-quangguo-3.ovpn>Dmg-yd-new-quanguo.ovpn

echo "# 大猫哥云免配置 新移动全国3-广州安徽测试通过
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote jl.12530.com 80
########免流代码########
http-proxy $IP 138
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-gzah-1.ovpn
echo 'http-proxy-option EXT1 POST http://jl.12530.com
http-proxy-option EXT1 "X-Online-Host:jl.12530.com"
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
'>http-yd-gzah-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-gzah-3.ovpn
cat http-yd-gzah-1.ovpn http-yd-gzah-2.ovpn http-yd-gzah-3.ovpn>Dmg-yd-gzan.ovpn

echo "# 大猫哥云免配置 新移动全国1-广东清远测试通过
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote a.mll.migu.cn 3389 tcp-client
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-yd-gdqy-1.ovpn
echo 'http-proxy-option EXT1 "User-Agent: migumusic" 
http-proxy-option EXT1 "GET /rdp2/v5.4/template/14018427/images/2.jpg HTTP/1.1" 
http-proxy-option EXT1 "/rdp2/migusdk/tokenValidate.do?ua=Android_sst&version=4.3040 HTTP/1.1" 
http-proxy-option EXT1 "Host: a.mll.migu.cn"
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
'>http-yd-gdqy-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-yd-gdqy-3.ovpn
cat http-yd-gdqy-1.ovpn http-yd-gdqy-2.ovpn http-yd-gdqy-3.ovpn>Dmg-lt-qgqy.ovpn

echo "# 大猫哥云免配置 联通新uac全国
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote uac.10010.com/index.asp&from=http://$IP:440?uac.10010.com/index.asp&from=uac.10155.com/index.asp&& 440
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-lt-qg-uac-1.ovpn
echo 'http-proxy-option EXT1 "Referer: http://uac.10010.com/oauth2/new_auth?display=wap&page_type=05&app_code=ECS-YH-WAP&redirect_uri=http://wap.10010.com/t/loginCallBack.htm&state=http://wap.10010.com/t/home.htm&channel_code=113000001&real_ip=$IP"
http-proxy-option EXT1 "POST http://m.client.10010.com"
http-proxy-option EXT1 "GET http://m.client.10010.com"
http-proxy-option EXT1 ": http://uac.10010.com/"
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
'>http-lt-qg-uac-2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">http-lt-qg-uac-3.ovpn
cat http-lt-qg-uac-1.ovpn http-lt-qg-uac-2.ovpn http-lt-qg-uac-3.ovpn>Dmg-lt-qg-uac.ovpn

echo "# 大猫哥云免配置 联通全国3
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote mob.10010.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-lt-quanguo11.ovpn
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
cat http-lt-quanguo11.ovpn http-lt-quanguo22.ovpn http-lt-quanguo33.ovpn>Dmg-lt-3.ovpn


echo "# 大猫哥云免配置 联通广东
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote wap.17wo.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-lt-guangdong1.ovpn
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
cat http-lt-guangdong1.ovpn http-lt-guangdong2.ovpn http-lt-guangdong3.ovpn>Dmg-lt-gd.ovpn


echo "# 大猫云免配置 联通全国复活
# 本文件由系统自动生成
# 类型：常规类型
client
dev tun
proto tcp
remote $IP $vpnport
########免流代码########
http-proxy-option VERSION 1.1
http-proxy $IP 28080">lt-quanguo123.ovpn
echo 'http-proxy-option EXT1 "Host: sales.wostore.cn:8081"
http-proxy-option EXT1 "Proxy-Connection: keep-alive"
########免流代码########
<http-proxy-user-pass>
dmgmll
dmgmll
</http-proxy-user-pass>
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>lt-quanguo223.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">lt-quanguo323.ovpn
cat lt-quanguo123.ovpn lt-quanguo223.ovpn lt-quanguo323.ovpn>Dmg-lt-28080-qg.ovpn

echo "# # 大猫云免配置 电信世纪龙
# 本文件由系统自动生成
# 类型：常规类型
client
dev tun
proto tcp
########免流代码########
remote 123.206.43.23/flowfreecontent 80
http-proxy $IP 8080">dxsjl1.ovpn
echo 'http-proxy-option EXT1 "GET /flowfreecontent/"
http-proxy-option EXT1 "Host：118.123.170.20"
########免流代码########
<http-proxy-user-pass>
dmgmll
dmgmll
</http-proxy-user-pass>
resolv-retry infinite
nobind
persist-key
persist-tun
setenv IV_GUI_VER "de.blinkt.openvpn 0.6.17"
machine-readable-output
connect-retry-max 5
connect-retry 5
resolv-retry 60
auth-user-pass
ns-cert-type server
comp-lzo
verb 3
'>dxsjl2.ovpn
echo "## 证书
<ca>
`cat ca.crt`
</ca>
key-direction 1
<tls-auth>
`cat ta.key`
</tls-auth>
">dxsjl3.ovpn
cat dxsjl1.ovpn dxsjl2.ovpn dxsjl3.ovpn>Dmg-dx-sjl.ovpn

echo "# 大猫哥云免配置 电信爱看
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote ltetptv.189.com 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">111dx1.ovpn
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
cat 111dx1.ovpn http-dx2.ovpn http-dx3.ovpn>Dmg-dx-1.ovpn

echo "# 大猫哥云免配置 电信爱玩
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote cdn.4g.play.cn 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-dx12.ovpn
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
cat http-dx12.ovpn http-dx22.ovpn http-dx33.ovpn>Dmg-dx-2.ovpn

echo "# 大猫哥云免配置 电信常规-测试免广东-大猫哥自用广东电信
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
dmgmll
dmgmll
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
cat 111a31.ovpn 11adx32.ovpn aa333.ovpn>Dmg-dx-3.ovpn

echo "# 大猫哥云免配置 移动全国5
# 本文件由系统自动生成
# 类型：3-HTTP转接类型
client
dev tun
proto tcp
remote $IP 80
########免流代码########
http-proxy $IP $mpport
http-proxy-option EXT1 dmgmll 127.0.0.1:$vpnport">http-ydyd.ovpn
echo 'http-proxy-option EXT1 "POST http://rd.go.10086.cn/ HTTP/1.1"
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
cat http-ydyd.ovpn http-ydyd2.ovpn http-ydyd3.ovpn>Dmg-yd-5.ovpn



echo
echo "配置文件制作完毕"
echo
echo "正在生成Android应用..."
echo
yum install -y java >/dev/null 2>&1
cd /root
sed -i 's/大猫哥流量/'$webname'/g' zdmc.sql >/dev/null 2>&1
sed -i 's/ov/'${bb}'/g' zdmc.sql >/dev/null 2>&1
sed -i 's/123123/'$qie'/g' zdmc.sql >/dev/null 2>&1
sed -i "s/dmg-dl/`echo $RANDOM`/g" zdmc.sql >/dev/null 2>&1
sed -i 's/123456789/'$adminuser'/g' zdmc.sql >/dev/null 2>&1
sed -i 's/987654321/'$adminzanshi'/g' zdmc.sql >/dev/null 2>&1
mysql -hlocalhost -uroot -p$sqlpass --default-character-set=utf8<<EOF
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'IDENTIFIED BY '${sqlpass}' WITH GRANT OPTION;
flush privileges;
use ${bb};
source zdmc.sql;
source open.sql;
EOF
rm -rf *.sql
cd /home
mkdir android
chmod 777 /home/android
cp /root/dmg/web/zdmc.sql /home/android/ >/dev/null 2>&1
cd /home/android

curl -O ${http}${Host}/${Vpnfile}/apktool.jar
echo
curl -O ${http}${Host}/${Vpnfile}/Dmg-Yunduanap.apk
echo
java -jar apktool.jar d Dmg-Yunduanap.apk

sed -i 's/127.0.0.1/'${IP}:${port}'/g' /home/android/Dmg-Yunduanap/smali/net/openvpn/openvpn/ModelBase.smali >/dev/null 2>&1
sed -i 's/127.0.0.1/'${IP}:${port}'/g' /home/android/Dmg-Yunduanap/smali/net/openvpn/openvpn/MainActivity.smali >/dev/null 2>&1
sed -i 's/127.0.0.1/'${IP}:${port}'/g' /home/android/Dmg-Yunduanap/smali/net/openvpn/openvpn/AutoScrollTextView.smali >/dev/null 2>&1
sed -i 's/云流量/'$app_name'/g' /home/android/Dmg-Yunduanap/res/values/strings.xml >/dev/null 2>&1
sed -i 's/全网流量，尽在大猫哥/'$app_name1'/g' /home/android/Dmg-Yunduanap/res/values/strings.xml >/dev/null 2>&1
echo
sudo chmod +x /home/android/apktool.jar
echo
java -jar apktool.jar b Dmg-Yunduanap
echo
cd /home/android/Dmg-Yunduanap/dist
echo
wget ${http}${Host}/${Vpnfile}/signer.tar.gz >/dev/null 2>&1
tar zxf signer.tar.gz
java -jar signapk.jar testkey.x509.pem testkey.pk8 Dmg-Yunduanap.apk dmgml.apk
\cp -rf /home/android/Dmg-Yunduanap/dist/dmgml.apk /home/Dmg-Yunduanap.apk


cd /home
cp Dmg-Yunduanap.apk /home/wwwroot/default/Dmg-Yunduanap.apk >/dev/null 2>&1
tar -zcvf ${uploadfile} ./{Dmg-dx-sjl.ovpn,Dmg-lt-gd-zl.ovpn,Dmg-lt-qg-uac.ovpn,Dmg-lt-qgqy.ovpn,Dmg-yd-zjmm.ovpn,Dmg-yd-new-quanguo.ovpn,Dmg-yd-gzan.ovpn,Dmg-yd-new-quanguo2.ovpn,Dmg-yd-new-quanguo3.ovpn,Dmg-yd-new-gd.ovpn,Dmg-lt-4-quanguo.ovpn,Dmg-lt-28080-qg.ovpn,Dmg-yd-quanguo-udp-137.ovpn,Dmg-yd-sc.ovpn,Dmg-yd-1.ovpn,Dmg-yd-2.ovpn,Dmg-yd-3.ovpn,Dmg-yd-4.ovpn,Dmg-yd-gd.ovpn,Dmg-yd-gx.ovpn,Dmg-yd-zj.ovpn,Dmg-lt-UAC-2.ovpn,Dmg-lt-gd.ovpn,Dmg-dx-1.ovpn,Dmg-dx-2.ovpn,Dmg-dx-3.ovpn,Dmg-yd-5.ovpn,Dmg-Yunduanap.apk,Dmg-lt-3.ovpn,ca.crt,ta.key,info.txt} >/dev/null 2>&1
echo
echo "正在上传文件中..."
echo "温馨提示："
echo "上传需要几分钟具体时间看你服务器配置"
echo "再此期间请耐心等待！"
sleep 2
echo
curl --upload-file ./${uploadfile} ${http}${upload}/${uploadfile} >/dev/null 2>&1 >url


cp /root/ca.crt /home/wwwroot/default/ >/dev/null 2>&1
cp /root/ta.key /home/wwwroot/default/ >/dev/null 2>&1
echo
echo "正在上传apk文件..."
clear

rm -rf android
rm -rf *.ovpn
rm -rf dmg.apk
if [ $llwsapp == "1" ];then
liuliangweishi
fi
return 1
}

function shujukubeifen(){
wget -P /home ${http}${Host}/${Vpnfile}/backupsql.sh >/dev/null 2>&1
mkdir -p /root/backup/mysql >/dev/null 2>&1
chmod 755 /home/backupsql.sh >/dev/null 2>&1
}

function shuchuliuliangweishianzhuangxinxi(){
	chattr -i /home/wwwroot/default/app_api/ >/dev/null 2>&1
	echo "安装完成，请您重新访问配置面板">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "http://$IP:$port/app_api/install">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "运行云端安装向导">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "APP请在">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "http://$IP:$port/app_api/dingd.apk">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "下载">>info.txt
	echo "------------------------------------------------------------">>info.txt
	echo "请激活默认线路后，再进行配置流量卫士即可同步线路">>info.txt
	echo "------------------------------------------------------------">>info.txt
}


function webmlpass() {
cd /home
shujukubeifen
bash backupsql.sh
echo '欢迎使用大猫哥™OpenVPN云免快速安装脚本' >>info.txt
echo
if [ $llwsapp == "1" ];then
shuchuliuliangweishianzhuangxinxi
fi
echo
echo "
前台/用户中心，用户查流量的地址：${IP}:${port}  
------------------------------------------------------------
后台管理系统：${IP}:${port}/admin
------------------------------------------------------------
代理中心：${IP}:${port}/daili 代理中心
------------------------------------------------------------
数据库后台：${IP}:${port}/$phpmyadminsuijishu 
------------------------------------------------------------


您的数据库用户名：root 数据库密码：${sqlpass} 数据库名：${bb}
------------------------------------------------------------
后台管理员用户名：$adminuser 管理密码：$adminzanshi
------------------------------------------------------------
流控网页程序文件目录为:/home/wwwroot/default/
------------------------------------------------------------
您当前${llwssfyaz}安装流量卫士 （流量卫士默认权限与流控一致）
------------------------------------------------------------
数据库每1分钟自动备份，备份数据库文件在/root/backup/mysql/
------------------------------------------------------------

温馨提示： 
------------------------------------------------------------
请您登录流控打开“云端管理->激活线路”，进行线路激活
------------------------------------------------------------
Dmg-yd 表示移动线路 Dmg-lt 表示联通线路  Dmg-dx 表示电信线路
------------------------------------------------------------
自带APP会报毒 属于误报，请各位用户自行加壳
------------------------------------------------------------
">>info.txt



return 1
}
function pkgovpn() {
clear
echo "正在打包配置文件，请稍等..."
echo
sleep 2
cd /home/




clear
rm -rf *.ovpn
echo
echo "配置文件已经上传完毕！正在加载您的配置信息..."
echo
cat info.txt
echo 
echo "您的线路/证书/key/云端APP/等重要内容下载地址如下："
echo
cat url
\cp -rf /home/${uploadfile} /home/wwwroot/default/${uploadfile}
echo 
echo "备用下载链接：http://${IP}:${port}/${uploadfile}"
echo 
echo "您的IP是：$IP （如果与您实际IP不符合或空白，请自行修改.ovpn配置）"

chattr +i /home/wwwroot/default/ && chattr -i /home/wwwroot/default/res/ && chattr -i /home/wwwroot/default/udp/ && chattr +i /home/wwwroot/default/user/ && chattr +i /home/wwwroot/default/config.php && chattr +i /home/wwwroot/default/admin/ && chattr +i /home/wwwroot/default/api.inc.php && chattr +i /home/wwwroot/default/daili/ && chattr +i /home/wwwroot/default/down/ && chattr +i /home/wwwroot/default/pay/ && chattr +i /home/wwwroot/default/web/ && chattr +i /home/wwwroot/default/360safe/
chmod -R 755 /home/wwwroot/default/$phpmyadminsuijishu  
chmod -R 777 /home >/dev/null 2>&1
chattr +i /home/wwwroot/default/$phpmyadminsuijishu
return 1
}
function main(){
shellhead
clear
echo -e '\033[33m================☆☆========================================================\033[0m'
echo -e '\033[33m                大猫哥免流-Web流控系统 云免服务器一键搭建           	   \033[0m'
echo -e '\033[33m                        Powered by dmkuai.com 2016         	               \033[0m'
echo -e '\033[33m                        All Rights Reserved         	                   \033[0m'
echo -e '\033[33m                交流群：383503746	  欢迎你的加入！				   \033[0m'
echo -e '\033[33m                本脚本已通过阿里云 腾讯云 小鸟云 等一系列服务器 	           \033[0m'
echo -e '\033[34m                官方网址：http://dmkuai.com/                        \033[0m'
echo -e '\033[34m                服务器重启之后出现502请使用脚本里502修复进行更新！\033[0m'
echo -e '\033[33m                请选择正版授权，提供安全到位的售后服务，谢谢！ \033[0m'
echo -e '\033[34m                谢谢各位猫友的支持！\033[0m'
echo -e '\033[34m                Cracked by：辣鸡小白 兔\033[0m'
echo -e '\033[34m================☆☆========================================================\033[0m'

echo 
authentication
InputIPAddress
clear
echo -e '\033[33m================☆☆========================================================\033[0m'
echo -e '\033[33m                大猫哥免流-Web流控系统 云免服务器一键搭建           	   \033[0m'
echo -e '\033[33m                温馨提示：         	                   \033[0m'
echo -e '\033[33m                为了您服务器的稳定和安全，请勿非法破解改程序               \033[0m'
echo -e '\033[33m                    支持正版，抵制盗版                           \033[0m'
echo -e '\033[33m                秘钥绑定IP可在同一IP下反复使用！				       \033[0m'
echo -e '\033[34m                    官方网址：http://dmkuai.com/  	                   \033[0m'
echo -e '\033[33m                交流群：383503746	  欢迎你的加入	  			   \033[0m'
echo -e '\033[34m                服务器重启之后出现502请使用脚本里502修复进行更新！\033[0m'
echo -e '\033[33m                请选择正版授权，提供安全到位的售后服务，谢谢！ \033[0m'
echo -e '\033[34m                谢谢各位猫友的支持！\033[0m'
echo -e '\033[34m                Cracked by：辣鸡小白 兔\033[0m'
echo -e '\033[34m================☆☆========================================================\033[0m'
echo
echo -e '\033[33m请输入正版密钥开启安装向导（购买地址:\033[32m http://www.dmkuai.com \033[0m）'
echo
echo  -n -e '\033[33m请输入授权密钥：\033[0m'
read card
echo
echo "正在验证授权码..."
#ccard=$(mysql -s -h${mysqlip} -u${mysql} -p${mysqlpasswd} -e "use card;SELECT card FROM card WHERE card='$card'";)
kcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;nginxcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;httpdcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;
if [[！"$kcard" == "" ]]
then

echo -e '\033[33m==========================================================================\033[0m'
echo -e '\033[34m               密钥错误 请检查授权码是否输入正确！           	       \033[0m'
echo -e '\033[31m               温馨提示：         	                   \033[0m'
echo -e '\033[31m               为了您服务器的稳定和安全，请勿非法破解改程序               \033[0m'
echo -e '\033[33m               正版密钥15元一个                           \033[0m'
echo -e '\033[31m               密钥绑定IP可在同一IP下反复使用！				       \033[0m'
echo -e '\033[33m               官方网址：http://dmkuai.com/  	                   \033[0m'
echo -e '\033[31m               交流群：383503746	  欢迎你的加入	  			   \033[0m'
echo -e '\033[33m==========================================================================\033[0m'
		echo
		exit 0;
else
IP2=`curl -s http://members.3322.org/dyndns/getip`;
if [[ "$kcard" == "no" ]]
then
echo
echo -e '授权状态          [\033[32m  授权成功  \033[0m]';
echo "此授权码已成功绑定您的服务器IP，支持永久无限使用！";
echo "即将开始下一步安装..."
#mysql -h${mysqlip} -u${mysql} -p${mysqlpasswd} -e "use card;DELETE FROM card WHERE card='$card';"
clear
echo "请选择安装类型："
echo 
echo "1 - 全新安装(回车默认) < 新装+流控系统"
echo -e "        \033[31m注意：\033[0m\033[35m支持阿里云、腾讯云等正规服务商 Centos7.x 全新系统. \033[0m"
echo -e "        \033[31m\033[0m\033[35m开放多端口新增UDP-TCP共存 实时监控 等... \033[0m"
echo -e "        腾讯云：请默认安全组放通全部端口."
echo
echo "2 - 修复模式 >> 流控502错误更新"
echo -e "        \033[31m注意\033[0m\033[35m. \033[0m"
echo -e "        重启服务器流控502请选择此项修复."
echo
echo "3 - 对接模式 >> 实现N台服务器共用账号"
echo -e "        \033[31m提示：\033[0m\033[35m. \033[0m"
echo -e "        一键配置共用数据库，需负载均衡，请自行同步证书，并用阿里云域名进行负载均衡"
echo -e "        请用需要对接主服务器的子服务器执行此选项完成对接"
echo
# echo "4 - 补丁安装 >> 一键安装sql防注入补丁"
# echo -e "        \033[31m提示：\033[0m\033[35m. \033[0m"
# echo -e "        该补丁解决通过原版openvpn注入sql问题，拦截空格特殊字符等"
# echo
echo -n -e "请输入对应的选项:"
read installslect


if [[ "$installslect" == "3" ]]
then
clear
echo "-------------------------------------------"
echo "负载均衡必看说明："
echo "两台服务器必须都已安装大猫哥流控"
echo "并能正常运行和链接服务器"
echo "且数据库账号-密码-端口-管理员账号-密码 需保持一致！"
echo "-------------------------------------------"
echo
echo "请提供主服务器和副机信息:"
echo -e "      \033[31m注意：\033[0m\033[35m请如实填写信息，否则后果自负！. \033[0m"
echo -e "      请核对仔细无错后再进行回车."
echo
echo -n -e "请输入主服务器的IP地址:"
read mumjijiipaddress
echo
echo -n -e "请输入当前服务器数据库名字"
read dangqianshujukumingzi
echo
echo -n -e "请输入主服务器的数据库名字:"
read zhushujukumingzi
echo
echo -n -e "请输入主服务器的数据库密码:"
read mumjijisqlpass
echo
echo -n -e "请输入当前服务器数据库密码："
read sbsonsqlpass
echo
echo "您当前主机是否已安装流量卫士？"
echo "1-已安装"
echo "2-未安装"
echo -n -e "请输入选项（1或2）："
read llwsshifouanzhuang
echo
echo "您保存的配置如下："
echo -e "\033[31m-------------------------------------------\033[0m"
echo "主服务器服务器:$mumjijiipaddress"
echo "当前数据库名字:$dangqianshujukumingzi"
echo "主服务器数据库名字:$zhushujukumingzi"
echo "主服务器数据库密码:$mumjijisqlpass"
echo "副机的数据库密码：$sbsonsqlpass"
echo -e "\033[31m-------------------------------------------\033[0m"
echo -e "\033[31m注意：\033[0m\033[35m \033[0m"
echo -e "\033[33m如信息无误请回车开始配置.\033[0m"
echo -e "\033[33m如果信息有错请按 Ctrl + c 键结束对接，并重新执行对接脚本！\033[0m"

echo -e "\033[35m回车开始执行配置 >>>\033[0m"
read
echo "正在配置数据 请稍等..."
chattr -i /home/wwwroot/default/ && chattr -i /home/wwwroot/default/config.php
sed -i 's/localhost/'$mumjijiipaddress'/g' /home/wwwroot/default/config.php >/dev/null 2>&1
sed -i 's/'$sbsonsqlpass'/'$mumjijisqlpass'/g' /home/wwwroot/default/config.php >/dev/null 2>&1
sed -i 's/'$dangqianshujukumingzi'/'$zhushujukumingzi'/g' /home/wwwroot/default/config.php >/dev/null 2>&1
sed -i 's/'$sbsonsqlpass'/'$mumjijisqlpass'/g' /etc/openvpn/dmkuai >/dev/null 2>&1
sed -i 's/'$dangqianshujukumingzi'/'$zhushujukumingzi'/g' /etc/openvpn/dmkuai >/dev/null 2>&1
sed -i 's/localhost/'$mumjijiipaddress'/g' /etc/openvpn/dmkuai.cfg >/dev/null 2>&1
sed -i 's/'$sbsonsqlpass'/'$mumjijisqlpass'/g' /etc/openvpn/sqlmima >/dev/null 2>&1
sed -i 's/'$dangqianshujukumingzi'/'$zhushujukumingzi'/g' /etc/openvpn/sqlmima >/dev/null 2>&1
if [[ "$llwsshifouanzhuang" == "1" ]]
then
echo "Currently installed traffic guards."
else
sed -i 's/localhost/'$mumjijiipaddress'/g' /etc/openvpn/disconnect.sh >/dev/null 2>&1
sed -i 's/'$dangqianshujukumingzi'/'$zhushujukumingzi'/g' /etc/openvpn/disconnect.sh >/dev/null 2>&1
sed -i 's/'$sbsonsqlpass'/'$mumjijisqlpass'/g' /etc/openvpn/disconnect.sh >/dev/null 2>&1
fi
mysql -hlocalhost -uroot -p$sbsonsqlpass --default-character-set=utf8<<EOF
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'IDENTIFIED BY '${sbsonsqlpass}' WITH GRANT OPTION;
flush privileges;
EOF
vpn >/dev/null 2>&1
echo
chattr +i /home/wwwroot/default/ && chattr +i /home/wwwroot/default/config.php
echo -e "\033[31m配置完成!\033[0m"
echo -e "\033[33m成功与主服务器IP:$mumjijiipaddress 对接成功\033[0m"
echo -e "\033[35m请自行到主服务器后台添加当前服务器 $IP\033[0m"
exit 0;
fi




if [[ "$installslect" == "4" ]]
then	
clear
echo "SQL防注入补丁安装："
echo "2016年11月16日之后安装的流控无需安装此补丁"
echo "流控已经自带防注入"
echo "此补丁提供11/16日前的老用户安装使用"
echo "请务必选择正确！"
echo
echo -e '\033[33m1 - 普通用户 ->\033[32m 安装选择我\033[0m）'
echo "    单个服务器没有集群负载的用户请选择我！"
echo
echo -e '\033[33m2 - 集群负载用户\033[32m 安装选择我\033[0m）'
echo "    已经集群负载的用户 请选择我！"
echo
echo -n -e "请输入对应的选项:"
read sqlzhuru

	if [[ "$sqlzhuru" == "1" ]];then
		echo
				
					# echo "您是否需要备份当前文件"
					# echo
					# echo -e '\033[33m1 - 我要\033[32m 备份\033[0m'
					# echo
					# echo -e '\033[33m2 - 我不需要\033[32m 备份\033[0m'
					# echo
					# echo -n -e "请输入对应的选项:"
					# read beifen
					# if [ "$beifem" == "1" ];then
						# cd /etc/openvpn
						# mv login.sh login.sh~
						# echo "你已经成功备份文件"
						# echo "当前备份文件名为login.sh~"
						# return 1
					# else
						# if [ "$beifem" == "2" ];then
							# rm -f login.sh
						# else
							# echo "输入错误请重新执行脚本！"
							# return 1
						# fi
					# fi
		# echo
		echo "正在为您备份login.sh文件"
		sleep 2
		cd /etc/openvpn
		mv login.sh login.sh~
		echo "当前备份文件名为login.sh~"
		echo -n -e "请输入您的数据库名字："
		read sqlzhurukuming
		echo -n -e "请输入您的数据库密码："
		read sqlshujukumima
		echo
		echo -n -e "确认无误回车开始安装补丁--->"
		read
		cd /root
		wget ${http}${Host}/${Vpnfile}/login.sh >/dev/null 2>&1
		\cp -rf /root/login.sh /etc/openvpn/login.sh
		sed -i 's/9520RANDOM/'$sqlzhurukuming'/g' /etc/openvpn/login.sh >/dev/null 2>&1
		sed -i 's/Dmgsql/'$sqlshujukumima'/g' /etc/openvpn/login.sh >/dev/null 2>&1
		echo
		cd /etc/openvpn
		chmod 777 login.sh
		clear
		echo "sql补丁安装完成"
		return 1
	else
		if [[ "$sqlzhuru" == "2" ]];then
				echo
				# echo "您是否需要备份当前文件"
				# echo
				# echo -e '\033[33m1 - 我要 ->\033[32m 备份\033[0m）'
				# echo
				# echo -e '\033[33m2 - 我不需要\033[32m 备份\033[0m）'
				# echo
				# echo -n -e "请输入对应的选项:"
				# read beifen
						
						# if [[ "$beifem" == "1" ]];then
							# cd /etc/openvpn
							# mv login.sh login.sh~
							# echo "你已经成功备份文件"
							# echo "当前备份文件名为login.sh~"
							# return 1
						# else
							# if [[ "$beifem" == "2" ]];then
								# rm -f login.sh
							# else
								# echo "输入错误请重新执行脚本！"
								# return 1
							# fi
						# fi
				echo "正在为您备份login.sh文件"
				sleep 2
				cd /etc/openvpn
				mv login.sh login.sh~
				echo "当前备份文件名为login.sh~"
				echo -n -e "请输入主服务器数据库名字："
				read sqlzhurukuming
				echo -n -e "请输入主服务器数据库密码："
				read sqlshujukumima
				echo -n -e "请输入主服务器IP地址："
				read sqlshujukumiip
				echo
				echo -n -e "确认无误回车开始安装补丁--->"
				read
				cd /root
				wget ${http}${Host}/${Vpnfile}/login.sh >/dev/null 2>&1
				\cp -rf /root/login.sh /etc/openvpn/login.sh
				sed -i 's/9520RANDOM/'$sqlzhurukuming'/g' /etc/openvpn/login.sh >/dev/null 2>&1
				sed -i 's/Dmgsql/'$sqlshujukumima'/g' /etc/openvpn/login.sh >/dev/null 2>&1
				sed -i 's/localhost/'$sqlshujukumiip'/g' /etc/openvpn/login.sh >/dev/null 2>&1
				echo
				cd /etc/openvpn
		        chmod 777 login.sh
				clear
				echo "sql补丁安装完成"
				return 1
				fi
				
	fi
fi




if [[ "$installslect" == "2" ]];then	
	echo "正在开始处理更新..."	 
	wget ${http}${Host}/${Vpnfile}/${php} >/dev/null 2>&1
	chmod 777 atomic-ceshi-2 >/dev/null 2>&1
	sh ./atomic-ceshi-2
	yum -y install php  php-mysql php-gd libjpeg* php-imap php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-mcrypt php-bcmath php-mhash libmcrypt libmcrypt-devel php-fpm
	echo
	cd /etc/php-fpm.d/
	rm -rf ./www.conf >/dev/null 2>&1
	curl -O ${http}${Host}/${Vpnfile}/${www}
	chmod 0755 ./${www} >/dev/null 2>&1
		 
		echo '正在重启lnmp...'
		systemctl restart php-fpm.service
		echo -e '服务状态：			  [\033[32m  OK  \033[0m]'
			echo
			echo "更新完成"
			exit 0;
else
	vpnportseetings
	readytoinstall
	newvpn
	installlnmp
	webml
	echo
	echo -e "正在为您开启所有服务..."
	chmod 777 /home/wwwroot/default/res/*
	chmod 777 /home/wwwroot/default/udp/*
	cd /root
	chmod 0777 ./udp >/dev/null 2>&1
	./udp -l 138 -d >/dev/null 2>&1
	./udp -l 137 -d >/dev/null 2>&1
	./udp -l 8080 -d >/dev/null 2>&1
	./udp -l 351 -d >/dev/null 2>&1
	./udp -l 366 -d >/dev/null 2>&1
	./udp -l 3389 -d >/dev/null 2>&1
	./udp -l 28080 -d >/dev/null 2>&1
	ovpn
	webmlpass
	pkgovpn
fi
fi
fi
echo "$finishlogo";
rm -rf url >/dev/null 2>&1
rm -rf /etc/openvpn/ca >/dev/null 2>&1
return 1
}
main
exit 0;
#版权所有：大猫哥免流 
