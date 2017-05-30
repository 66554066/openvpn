#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=================================================================#
#   System Required:  CentOS 6,7, Debian, Ubuntu                  #
#   Description: One click Install ShadowsocksR Server            #
#   Author: hugoyuice <https://twitter.com/hugoyuice>             #
#   Thanks: @breakwa11 <https://twitter.com/breakwa11>            #
#   Thanks: @Teddysun <i@teddysun.com>                            #
#   Intro:  https://shadowsocks.be/9.html     
 #本脚本由奔放网benfw.cn提供                   #
#=================================================================#

clear
echo

echo

#Current folder
cur_dir=`pwd`
# Get public IP address
IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
if [[ "$IP" = "" ]]; then
    IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
fi

# Make sure only root can run our script
function rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "错误：需要使用root账户!" 1>&2
       exit 1
    fi
}

# Check OS
function checkos(){
    if [ -f /etc/redhat-release ];then
        OS='CentOS'
    elif [ ! -z "`cat /etc/issue | grep bian`" ];then
        OS='Debian'
    elif [ ! -z "`cat /etc/issue | grep Ubuntu`" ];then
        OS='Ubuntu'
    else
        echo "当前系统不支持搭建SSR!"
        exit 1
    fi
}

# Get version
function getversion(){
    if [[ -s /etc/redhat-release ]];then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else    
        grep -oE  "[0-9.]+" /etc/issue
    fi    
}

# CentOS version
function centosversion(){
    local code=$1
    local version="`getversion`"
    local main_ver=${version%%.*}
    if [ $main_ver == $code ];then
        return 0
    else
        return 1
    fi        
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

# Pre-installation settings
function pre_install(){
    # Not support CentOS 5
    if centosversion 5; then
        echo "Not support CentOS 5, please change OS to CentOS 6+/Debian 7+/Ubuntu 12+ and retry."
        exit 1
    fi
    # Set ShadowsocksR config password
    echo "- - - -- - - - - - - -- - - - - -- - - - - -- - - - - -- - - - - -- "
echo "     欢迎使用一键部署多端口SSR脚本"
  echo "- - - -- - - - - - - -- - - - - -- - - - - -- - - - - -- - - - - -- "
    echo "设置ShadowsocksR连接密码:"
    read -p "(默认密码是benfw.cn):" shadowsockspwd
    [ -z "$shadowsockspwd" ] && shadowsockspwd="benfw.cn"
    echo
    echo "---------------------------"
    echo "password = $shadowsockspwd"
    echo "---------------------------"
    echo
    # Set ShadowsocksR config port
    while true
    do
    echo -e "设置第一个远程端口 [1-65535]:"
    read -p "(默认端口: 80):" shadowsocksport
    [ -z "$shadowsocksport" ] && shadowsocksport="80"
    echo -e "设置第二个远程端口 [1-65535]:"
    read -p "(默认端口: 8080):" shadowsocksport2
    [ -z "$shadowsocksport2" ] && shadowsocksport2="8080"
    echo -e "设置第三个远程端口 [1-65535]:"
    read -p "(默认端口: 138):" shadowsocksport3
    [ -z "$shadowsocksport3" ] && shadowsocksport3="138"
    echo -e "设置第四个远程端口 [1-65535]:"
    read -p "(默认端口: 137):" shadowsocksport4
    [ -z "$shadowsocksport4" ] && shadowsocksport4="137"
    echo -e "设置第五个远程端口 [1-65535]:"
    read -p "(默认端口: 53):" shadowsocksport5
    [ -z "$shadowsocksport5" ] && shadowsocksport5="53"
    expr $shadowsocksport + 0 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ $shadowsocksport -ge 1 ] && [ $shadowsocksport -le 65535 ]; then
            echo
            echo "---------------------------"
            echo "port = $shadowsocksport"
            echo "---------------------------"
            echo
            break
        else
            echo "输入端口不规范"
        fi
    else
        echo "密码不规范"
    fi
    done
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo
    echo "按回车开始自动搭建！"
    char=`get_char`
    # Install necessary dependencies
    if [ "$OS" == 'CentOS' ]; then
        yum install -y wget unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent git ntpdate
        yum install -y m2crypto automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
    else
        apt-get -y update
        apt-get -y install python python-dev python-pip python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential git ntpdate
    fi
    cd $cur_dir
}

# Download files
function download_files(){
    # Download libsodium file
    if ! wget --no-check-certificate -O libsodium-1.0.10.tar.gz https://git.oschina.net/ben123pw/BFW/raw/master/libsodium-1.0.10.tar.gz; then
        echo "Failed to download libsodium file!"
        exit 1
    fi
    # Download ShadowsocksR file
    # if ! wget --no-check-certificate -O manyuser.zip https://git.oschina.net/ben123pw/BFW/raw/master/manyuser.zip; then
        # echo "Failed to download ShadowsocksR file!"
        # exit 1
    # fi
    # Download ShadowsocksR chkconfig file
    if [ "$OS" == 'CentOS' ]; then
        if ! wget --no-check-certificate https://git.oschina.net/ben123pw/BFW/raw/master/shadowsocksR -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    else
        if ! wget --no-check-certificate https://git.oschina.net/ben123pw/BFW/raw/master/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
            echo "Failed to download ShadowsocksR chkconfig file!"
            exit 1
        fi
    fi
}

# firewall set
function firewall_set(){
    echo "firewall set start..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep '${shadowsocksport}' | grep 'ACCEPT' > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo "port ${shadowsocksport} has been set up."
            fi
        else
            echo "WARNING: iptables looks like shutdown or not installed, please manually set it if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ];then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo "Firewalld looks like not running, try to start..."
            systemctl start firewalld
            if [ $? -eq 0 ];then
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
                firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
                firewall-cmd --reload
            else
                echo "WARNING: Try to start firewalld failed. please enable port ${shadowsocksport} manually if necessary."
            fi
        fi
    fi
    echo "firewall set completed..."
}

# Config ShadowsocksR
function config_shadowsocks(){
    cat > /etc/shadowsocks.json<<-EOF
{
 "server": "0.0.0.0",
 "server_ipv6": "::",
 "local_address": "127.0.0.1",
 "local_port":1080,
 "port_password":{
 "${shadowsocksport}":"${shadowsockspwd}",
 "${shadowsocksport2}":"${shadowsockspwd}",
 "${shadowsocksport3}":"${shadowsockspwd}",
 "${shadowsocksport4}":"${shadowsockspwd}",
 "${shadowsocksport5}":"${shadowsockspwd}"
},
 "timeout": 300,
 "udp_timeout": 60,
 "method": "aes-256-cfb",
 "protocol": "origin",
 "protocol_param": "",
 "obfs": "http_simple",
 "obfs_param": "",
 "dns_ipv6": false,
 "connect_verbose_info": 0,
 "redirect": "",
 "fast_open": false,
 "workers": 1

}
EOF
}

# Install ShadowsocksR
function install_ss(){
    # Install libsodium
    tar zxf libsodium-1.0.10.tar.gz
    cd $cur_dir/libsodium-1.0.10
    ./configure && make && make install
    echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf
    ldconfig
    # Install ShadowsocksR
    cd $cur_dir
    # unzip -q manyuser.zip
    # mv shadowsocks-manyuser/shadowsocks /usr/local/
	git clone -b manyuser https://github.com/breakwa11/shadowsocks.git /usr/local/shadowsocks
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x /etc/init.d/shadowsocks
        # Add run on system start up
        if [ "$OS" == 'CentOS' ]; then
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        else
            update-rc.d -f shadowsocks defaults
        fi
        # Run ShadowsocksR in the background
        /etc/init.d/shadowsocks start
        clear
        echo
        echo "恭喜你！ ShadowsocksR安装成功！"
        echo -e "服务器 IP: \033[41;37m ${IP} \033[0m"
        echo -e "远程端口: \033[41;37m ${shadowsocksport}、${shadowsocksport2}、${shadowsocksport3}、${shadowsocksport4}、${shadowsocksport5} \033[0m"
        echo -e "连接密码: \033[41;37m ${shadowsockspwd} \033[0m"
        echo -e "本地 IP: \033[41;37m 127.0.0.1 \033[0m"
        echo -e "本地端口: \033[41;37m 1080 \033[0m"
        echo -e "协议: \033[41;37m origin \033[0m"
        echo -e "混淆方式: \033[41;37m http_simple \033[0m"
        echo -e "加密方法: \033[41;37m aes-256-cfb \033[0m"
        echo
        echo "欢迎访问奔放网:http://benfw.cn"
        echo "基于shadowsocks.be的脚本修改版"
        echo
        echo "By:奔放网 Loser"
        echo
    else
        echo "Shadowsocks安装失败!"
        install_cleanup
        exit 1
    fi
}

#改成北京时间
function check_datetime(){
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	ntpdate 1.cn.pool.ntp.org
}

# Install cleanup
function install_cleanup(){
    cd $cur_dir
    rm -f manyuser.zip
    rm -rf shadowsocks-manyuser
    rm -f libsodium-1.0.10.tar.gz
    rm -rf libsodium-1.0.10
}


# Uninstall ShadowsocksR
function uninstall_shadowsocks(){
    printf "你确定要卸载ShadowsocksR?输入y确认 (y/n) "
    printf "\n"
    read -p "(Default: n):" answer
    if [ -z $answer ]; then
        answer="n"
    fi
    if [ "$answer" = "y" ]; then
        /etc/init.d/shadowsocks status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        checkos
        if [ "$OS" == 'CentOS' ]; then
            chkconfig --del shadowsocks
        else
            update-rc.d -f shadowsocks remove
        fi
        rm -f /etc/shadowsocks.json
        rm -f /etc/init.d/shadowsocks
        rm -rf /usr/local/shadowsocks
        echo "ShadowsocksR卸载成功!"
    else
        echo "uninstall cancelled, Nothing to do"
    fi
}


# Install ShadowsocksR
function install_shadowsocks(){
    checkos
    rootness
    disable_selinux
    pre_install
    download_files
    config_shadowsocks
    install_ss
    if [ "$OS" == 'CentOS' ]; then
        firewall_set > /dev/null 2>&1
    fi
	check_datetime
    install_cleanup
	
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
install)
    install_shadowsocks
    ;;
uninstall)
    uninstall_shadowsocks
    ;;
*)
    echo "Arguments error! [${action} ]"
    echo "Usage: `basename $0` {install|uninstall}"
    ;;
esac