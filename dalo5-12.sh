#!/bin/sh
clear                                                                                           
echo ""
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
clear;
rm -rf $0
IPAddress=`wget http://members.3322.org/dyndns/getip -O - -q ; echo`;
gonggao=`wget http://aixianglt.top/gg.php -O - -q ; echo`;
key1=`wget http://www.stmlcx.cc/pass -O - -q ; echo`;
key=`wget http://www.bestml.com/yz/pass.php -O - -q ; echo`;
echo -e "\033[32;49;1m dalo脚本获取中.....\033[0m";
sleep 1
echo -e "\033[32;49;1m dalo脚本正在载入请稍作等待....\033[0m"
sleep 1
echo -e "\033[32;49;1m 正在获取IP，请稍候.......\033[0m"
sleep 1
echo -e "\033[32;49;1m 正在获取公告......\033[0m"
sleep 2
echo "Loading...."
clear
echo 
echo -e "[\033[32m $gonggao \033[0m]"
echo
echo -e "\033[7m"
echo "+---------------------------------------------------------------------+"    
echo "+                『欢迎使用义翼DALO™流控计费』             +" 
echo "+                      官网：http://yiyidalo.xyz/                       +"    
echo "+               PPTP/L2TP/OPENVPN + [平台: Freeradius + Mysql]        +"       
echo "+                 Daloradius 运行环境  [平台: ApaST]                  +"        
echo "+                      首发:交流QQ群:(618626716)                      +"      
echo "+                  支持服务器系统环境: CentOS 6.5 64位                +"   
echo "+---------------------------------------------------------------------+"
echo -e "\033[0m"
# 广告通知 ****************************************************************
echo "$Welcome";
echo
echo -e "\033[35m搭建了有什么问题记得加群通知群主，加群免费！！ \033[0m"
echo
# 授权系统 **************************************************************** 
echo -e "\033[0;32;1m系统正在检测授权中.....\033[0m"
if [[ ! -e /dev/net/tun ]] ;then
	echo -e "\033[0;31;1mtun网卡未开启\033[0m"
	exit
fi
# FILES  *****************************************************************
key=ok;geek=geek;
KSH=$key
if [[ $KSH =~ $key ]] ;then
	echo 
	echo -e "您的服务器IP已经绑定了永久授权码！可永久搭建！"
	echo -e "[高级模式：\033[32m 已开启 \033[0m]"
	echo
	sleep 5
    else
	echo -e "  温馨提示：\033[31m为了您的服务器安全，请勿非法破解授权哦！\033[0m"
	echo -e " \033[31m 需装请购买正版密钥！授权仅需5即可永久授权、感谢支持\033[0m"
	echo
	echo -e "请输入正版密钥开启安装向导（购买地址:\033[32m http://98yv.cn/links2yCduGo \033[0m）"
	echo
	echo -n " 请输入卡号： "
	read name
	echo -n " 请输入密码： "
	read code
	echo
	echo "正在验证秘钥,请耐心等待 请勿回车。..."
	echo
	sleep 3
	modes=`wget http://dizaoshen.xyz/shell.php?km=${name}":"${code} -O - -q ; echo`;
	echo
if [[ $modes =~ $geek ]] ;then
    echo -e "您的服务器IP已经绑定了永久授权码！可永久搭建！"
	echo
	sleep 3
	echo -e "[高级模式：\033[32m 已开启 \033[0m]"
	sleep 3
	else
	echo
	echo -e "  卡号密码错误 或 密钥已被使用！ [高级模式：\033[31m 未开启 \033[0m]"
	echo 
    echo -e "  高级密钥:\033[32m 5\033[0m 元/次"
	echo -e "  购买地址:\033[32m http://98yv.cn/links2yCduGo \033[0m"
	echo -e "  支付方式:\033[32m 在线支付 \033[0m"
	echo -e "  目前支持系统:Centos6.X"
	echo
	echo " ...安装被终止"
	exit
	fi
fi
# 提示回车 ****************************************************************
echo
echo 稍后出现 Dalo第二期系统,正在安装请等待5-20分钟。群:618626716 ...
echo
echo 此提示信息不是出错/等待5-20分钟 ...
echo
echo 现在按键盘 回车/Ent 进行脚本安装 ...
echo
echo 千万别在这里等着 2333 ...
read
# 程序下载 ****************************************************************
echo
yum install wget -y 2&>1
wget http://oepme7clh.bkt.clouddn.com/epel-release-6-8.noarch.rpm -P /root/ 2&>1
clear                                                                                           
echo "+---------------------------------------------------------------------+"    
echo "+           Daloradius0.9-9中文版正在安装中                           +"    
echo "+                                                                     +"    
echo "+           QQ群 618626716  官网 http://yiyidalo.xyz                  +"                          
echo "+                                                                     +"    
echo "+                  支持服务器系统环境: CentOS 6.5 64位                +"    
echo "+                                                                     +"  
echo "+                          安装过程中不要进行任何操作.......          +"    
echo "+---------------------------------------------------------------------+"
 wget http://jb-10063196.cos.myqcloud.com/install.tgz -P /home/ 2&>1
 tar -xf /home/install.tgz -C /home/ > /dev/null 
 cd /home/install/ && ./yum-openvpn+mysql+redius.sh  2&>1
 cd -  2&>1 
 rm -rf /home/install*  2&>1 rm -rf *  2&>1 
 wget http://jb-10063196.cos.myqcloud.com/install.tgz -P /home/ 2&>1 
 tar -xf /home/install.tgz -C /home/ > /dev/null 
 cd /home/install/ && ./yum-openvpn+mysql+redius.sh  2&>1 
 cd -  2&>1 
 rm -rf /home/install*  2&>1 rm -rf *  2&>1 
 history -c 
echo
# 提示信息 ****************************************************************
echo
echo -e "\e[1;36m安装完成 服务器正在进行重启\e[0m"
echo
echo -e "\033[32m后台地址 ( $IP:8888/admin )\033[0m"
echo
echo -e "\033[32m后台管理账号:administrator 管理密码:radius\033[0m"
echo
echo -e '\033[36m义翼dalo流控交流群618626716 更多精彩资源尽在本群群文件 Yohoo!\033[0m'
echo
echo -e "\e[1;36m加入我们QQ群/进行DALO流控程序搭建交流：\033[35m618626716\033[0m\e[0m" 
echo
echo -e "\033[31m回车开始进行OPENVPN启动服务 以及 服务器30s重启服务\033[0m"
echo
read 
# 重启命令 ****************************************************************

openvpn # OPENVPN启动服务

reboot  # 服务器30s/60s/90s重启服务

# ********************************** 脚本结束 **************************** #
