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
	author=author-Dmg.tar.gz;
	RSA=wz-easy-rsa.tar.gz;
	line="xianlu.zip"
	Host='dmkuai.com';
	IP=`curl -s http://www.taobao.com/help/getip.php| egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1`;
	squser=auth_user;
	mysqlip='null';
	KRSA=easy-rsa.zip;
	line=line.zip;
	webupdatefile='Dmg-web-update.zip';
	webfile32='ioncube-32.tar.gz';
	webfile64='ioncube_loaders-64.tar.gz';
	phpmyadminfile='phpMyAdmin-4.0.10.15-all-languages.tar.gz';
	key=`curl -s http://dmkuai.com/Dmg-yanz`;
	upload=transfer.sh;
	jiankongfile='jiankong-6.zip';
	lnmpfile='Dmg-ceshi-lnmp.tar.gz';
	webfile='weijiamidabao.zip'; 
	uploadfile=Dmg-dmkuai-$RANDOM.zip;
	wget_host="zmker.oss-cn-shanghai.aliyuncs.com"
	files="files_v5"
	web_path="/home/wwwroot/default/"
	return 1
}
    function authentication() {
    echo -n -e "请输入大猫哥官方网址 [\033[32m $key \033[0m] ："
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
	yum -y install net-tools lsof psmisc >/dev/null 2>&1
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
	mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
	wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
	yum clean all >/dev/null 2>&1
	yum makecache >/dev/null 2>&1
	yum -y install epel-release
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
	yum install openvpn -y
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
	port=$port
	echo "[领取码生成授权码地址：www.dingd.cn] "
	echo -e "[请输入您在流量卫士官网通过验证领取的APP授权码（32位长度）]"
	read app_key
	curl "http://www.dingd.cn/api/check.php?domain=$domain&key=$app_key&t=dingd.cn" >> tmp.txt
	read status < tmp.txt
	rm tmp.txt
		if [ "success" = "$status" ]; then
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
[0]=time1.aliyun.com
[1]=time2.aliyun.com
[2]=time3.aliyun.com
[3]=time4.aliyun.com
[4]=time5.aliyun.com
[5]=time6.aliyun.com
[6]=time7.aliyun.com
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
mkdir /home/wwwroot/default/udp-53 >/dev/null 2>&1
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
    port 53
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
	management localhost 7507
	keepalive 10 120
	tls-auth /etc/openvpn/easy-rsa/ta.key 0  
	comp-lzo
	persist-key
	persist-tun
	status /home/wwwroot/default/udp-53/openvpn-status-udp-53.txt
	log openvpn2.log
	log-append  openvpn2.log
	verb 3
    #dmkuai.com" >/etc/openvpn/server-udp-53.conf
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
    port 53
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
	management localhost 7507
	keepalive 10 120
	tls-auth /etc/openvpn/easy-rsa/ta.key 0  
	comp-lzo
	persist-key
	persist-tun
	status /home/wwwroot/default/udp-53/openvpn-status-udp-53.txt
	log openvpn2.log
	log-append  openvpn2.log
	verb 3
    #dmkuai.com" >/etc/openvpn/server-udp-53.conf
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
killall dmproxy >/dev/null 2>&1
dmproxy -l $mpport -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 180 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 138 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 137 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 524 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 443 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 1026 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 8081 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 180 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 53 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 351 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 366 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 3389 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
dmproxy -l 28080 -h 127.0.0.1:$vpnport -d >/dev/null 2>&1
killall squid >/dev/null 2>&1
killall squid >/dev/null 2>&1
squid -z >/dev/null 2>&1
systemctl restart squid
lnmp
openvpn --config /etc/openvpn/server-udp.conf &
openvpn --config /etc/openvpn/server-udp-53.conf &
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
		mv /root/udp /bin/dmproxy
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
chmod 777 /bin/locksql
echo "echo -e '开启目录锁定		  [\033[32m  OK  \033[0m]'
chattr +i /home/wwwroot/default/ && chattr -i /home/wwwroot/default/res/ && chattr -i /home/wwwroot/default/udp/ && chattr +i /home/wwwroot/default/user/ && chattr +i /home/wwwroot/default/config.php && chattr +i /home/wwwroot/default/admin/ && chattr +i /home/wwwroot/default/api.inc.php && chattr +i /home/wwwroot/default/daili/ && chattr +i /home/wwwroot/default/down/ && chattr +i /home/wwwroot/default/pay/ && chattr +i /home/wwwroot/default/web/ && chattr +i /home/wwwroot/default/360safe/ && chattr +i /home/wwwroot/default/app_api/ >/dev/null 2>&1
exit 0;
" >/bin/lockdir
chmod 777 /bin/lockdir

echo "echo -e '关闭目录锁定		  [\033[32m  OK  \033[0m]'
chattr -i /home/wwwroot/default/ && chattr -i /home/wwwroot/default/res/ && chattr -i /home/wwwroot/default/udp/ && chattr -i /home/wwwroot/default/user/ && chattr -i /home/wwwroot/default/config.php && chattr -i /home/wwwroot/default/admin/ && chattr -i /home/wwwroot/default/api.inc.php && chattr -i /home/wwwroot/default/daili/ && chattr -i /home/wwwroot/default/down/ && chattr -i /home/wwwroot/default/pay/ && chattr -i /home/wwwroot/default/web/ && chattr -i /home/wwwroot/default/360safe/ && chattr -i /home/wwwroot/default/app_api/ >/dev/null 2>&1
exit 0;
" >/bin/ondir
chmod 777 /bin/ondir

echo "echo -e '监控启动完成		  [\033[32m  OK  \033[0m]'
/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 & /home/wwwroot/default/udp/jiankong >>/home/jiankong-udp.log 2>&1 &
exit 0;
" >/bin/opmt
chmod 777 /bin/opmt


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

mkdir -p /home/wwwroot/default/udp-53
cd /home/wwwroot/default/udp-53
curl -O ${http}${Host}/${Vpnfile}/udpjiankong-53.zip >/dev/null 2>&1
unzip udpjiankong-53.zip >/dev/null 2>&1
rm -rf udpjiankong-53.zip
chmod 777 jiankong
chmod 777 sha


sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/res/jiankong >/dev/null 2>&1
sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/udp/jiankong >/dev/null 2>&1
sed -i 's/shijian=30/'shijian=$jiankongs'/g' /home/wwwroot/default/udp-53/jiankong >/dev/null 2>&1

echo "mima=$sqlpass
databases="$bb"
shujuku="$bb"">>/etc/openvpn/sqlmima
chmod 777 /etc/openvpn/sqlmima
echo "db_pass="$sqlpass"
db_name="$bb"">>/etc/openvpn/dmkuai
chmod 777 /etc/openvpn/dmkuai

/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &
/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp.log 2>&1 &
/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp-53.log 2>&1 &
echo "/home/wwwroot/default/res/jiankong >>/home/jiankong.log 2>&1 &">>/etc/rc.local
echo "/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp.log 2>&1 &">>/etc/rcl.local
echo "/home/wwwroot/default/udp/jiankong >>/home/jiankong-udp-53.log 2>&1 &">>/etc/rcl.local
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
wget http://${Host}/${Vpnfile}/app_api-7.zip && unzip -o app_api-7.zip >/dev/null 2>&1
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
chmod 0777 -R /etc/openvpn/
cp -rf /etc/openvpn/disconnect.sh /etc/openvpn/disconnect.sh.bak 
cp -rf disconnect.sh /etc/openvpn/disconnect.sh
chmod 0777 /etc/openvpn/disconnect.sh
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
sed -i 's/APP_KEY_CODE/'${app_key}'/g' /home/android/smali/net/openvpn/openvpn/base.smali >/dev/null 2>&1
sed -i 's/demo.dingd.cn:80/'${domain}:${port}'/g' `grep demo.dingd.cn:80 -rl /home/android/smali/net/openvpn/openvpn/`  >/dev/null 2>&1
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
rm -rf /home/dingd.apk /home/sign.apk /home/unsign.apk /home/android.apk /home/android /home/autosign.zip /home/apktool.jar /home/setup.bash /home/autosign
llwssfyaz="已"
dadas="1"
fi
chmod -R 0555 /home/wwwroot/default/app_api/
chmod -R 0777 /home/wwwroot/default/app_api/data/
chattr +i /home/wwwroot/default/app_api/
return 1
}

function ovpn(){
echo
echo "正在生成Android应用..."
echo
yum install -y java >/dev/null 2>&1
cd /root
sed -i 's/大猫哥流量/'$webname'/g;s/ov/'${bb}'/g;s/123123/'$qie'/g;s/dmg-dl/`echo $RANDOM`/g;s/123456789/'$adminuser'/g;s/987654321/'$adminzanshi'/g' zdmc.sql >/dev/null 2>&1
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

sed -i 's/127.0.0.1/'${IP}:${port}'/g' `grep 127.0.0.1 -rl /home/android/Dmg-Yunduanap/smali/net/openvpn/openvpn/` >/dev/null 2>&1
sed -i 's/云流量/'${app_name}'/g;s/全网流量，尽在大猫哥/'${app_name1}'/g' /home/android/Dmg-Yunduanap/res/values/strings.xml >/dev/null 2>&1
echo
chmod +x /home/android/apktool.jar
echo
java -jar apktool.jar b Dmg-Yunduanap
echo
cd /home/android/Dmg-Yunduanap/dist
echo
wget ${http}${Host}/${Vpnfile}/signer.tar.gz >/dev/null 2>&1
tar zxf signer.tar.gz
java -jar signapk.jar testkey.x509.pem testkey.pk8 Dmg-Yunduanap.apk dmgml.apk
\cp -rf /home/android/Dmg-Yunduanap/dist/dmgml.apk /home/Dmg-Yunduanap.apk

echo 
echo "开始生成配置文件..."
sleep 3
mkdir -p /home/xianlu
cd /home/xianlu
curl -O ${http}${Host}/${Vpnfile}/${line}
unzip ${line} >/dev/null 2>&1
sed -i "s/localdmkuai/$IP/g;s/httpdmkuai/$mpport/g;s/portdmkuai/$vpnport/g" `grep 'localdmkuai' -rl .`
echo
echo "配置文件制作完毕"
cd /home
cp Dmg-Yunduanap.apk /home/wwwroot/default/Dmg-Yunduanap.apk >/dev/null 2>&1
cp Dmg-Yunduanap.apk /home/xianlu/Dmg-Yunduanap.apk >/dev/null 2>&1
cp info.txt /home/xianlu/info.txt >/dev/null 2>&1
cd /home/xianlu
zip ${uploadfile} `grep 'remote' -rl .` Dmg-Yunduanap.apk,ca.crt,ta.key,info.txt >/dev/null 2>&1
mv ${uploadfile} /home/${uploadfile} >/dev/null 2>&1
cd /home
rm -rf /home/xianlu
echo
echo "正在上传文件中..."
echo "温馨提示："
echo "上传需要几分钟具体时间看你服务器配置"
echo "再此期间请耐心等待！"
sleep 2
echo
curl --upload-file ./${uploadfile} ${http}${upload}/${uploadfile} >/dev/null 2>&1 >url
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
chmod -R 0755 /home/wwwroot/default/ && chmod -R 0755 /home/wwwroot/default/res/ && chmod -R 0755 /home/wwwroot/default/udp/ && chmod -R 0555 /home/wwwroot/default/user/ && chmod -R 0555 /home/wwwroot/default/config.php && chmod -R 0555 /home/wwwroot/default/admin/ && chmod -R 0555 /home/wwwroot/default/api.inc.php && chmod -R 0555 /home/wwwroot/default/daili/ && chmod -R 0555 /home/wwwroot/default/down/ && chmod -R 0555 /home/wwwroot/default/pay/ && chmod -R 0555 /home/wwwroot/default/web/ && chmod -R 0555 /home/wwwroot/default/360safe/ && chmod -R 0555 /home/wwwroot/default/assets/
chattr +i /home/wwwroot/default/ && chattr -i /home/wwwroot/default/res/ && chattr -i /home/wwwroot/default/udp/ && chattr +i /home/wwwroot/default/user/ && chattr +i /home/wwwroot/default/config.php && chattr +i /home/wwwroot/default/admin/ && chattr +i /home/wwwroot/default/api.inc.php && chattr +i /home/wwwroot/default/daili/ && chattr +i /home/wwwroot/default/down/ && chattr +i /home/wwwroot/default/pay/ && chattr +i /home/wwwroot/default/web/ && chattr +i /home/wwwroot/default/360safe/
chmod -R 0555 /home/wwwroot/default/$phpmyadminsuijishu  
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
echo -e '\033[34m================☆☆========================================================\033[0m'
echo
echo -e '\033[33m请输入正版密钥开启安装向导（购买地址:\033[32m http://www.dmkuai.com \033[0m）'
echo
echo  -n -e '\033[33m请输入授权密钥：\033[0m'
read card
echo
echo "正在验证授权码..."
kcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;nginxcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;httpdcard=`curl -s http://dmkuai.com/1183297959.php?card=${card}"&ip="${IP}`;
if [[ "$kcard" != "no" ]]
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
IP2=`curl -s http://www.taobao.com/help/getip.php| egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1`;
if [[ "$kcard" != "${card}-${IP2}" ]]
then
echo
echo -e '授权状态          [\033[32m  授权成功  \033[0m]';
echo "此授权码已成功绑定您的服务器IP，支持永久无限使用！";
echo "即将开始下一步安装..."
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
	chmod 0777 /bin/dmproxy >/dev/null 2>&1
	dmproxy -l 138 -d >/dev/null 2>&1
	dmproxy -l 137 -d >/dev/null 2>&1
	dmproxy -l 8080 -d >/dev/null 2>&1
	dmproxy -l 351 -d >/dev/null 2>&1
	dmproxy -l 366 -d >/dev/null 2>&1
	dmproxy -l 3389 -d >/dev/null 2>&1
	dmproxy -l 28080 -d >/dev/null 2>&1
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