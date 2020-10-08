
# 注意事项
还原包(使用镜像源加速)
* <code>pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple</code>

# 使用库
    scapy == 2.4.4
# **函数说明(Class Arp)**
- _init_(self)
- scan
- get_target
- arpspoof


# _init(self)
    初始化
    本机IP,网卡,网关,Mac地址
    靶机IP,Mac地址

# scan
    扫描网段下存在的主机
    把目标的IP以及MAC地址加入到result中,排序,遍历打印出相关信息

# get_target()
    选择主机ID,输入正确的数值跳出循环

# arpspoof
    构造包在使用scapy中的sendp()发送

# **效果**
    Windows下使用arp -a查看网关的mac地址变成攻击者的mac arp欺骗成功