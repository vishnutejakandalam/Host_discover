import scapy.all as scapy
from optparse import OptionParser

def nds(ip):
    print(ip)
    arpr=scapy.ARP(pdst=ip)
    ethr=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    tp=ethr/arpr
    answered=scapy.srp(tp,timeout=1,verbose=False)[0]
    for e in answered:
        print(e[1].psrc+"\t\t")
        print("\t\t")
        print(e[1].hwsrc)

def get_mac(ip):
    arpr=scapy.ARP(pdst=ip)
    ethr=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    tp=ethr/arpr
    ans=scapy.srp(tp,verbose=False,timeout=2)[0]
    ret_lst=[]
    for e in ans:
        ret_lst.append(e[1].hwsrc)
    return ret_lst
p=OptionParser()
p.add_option("-i","--ip",dest="ip_address",help="The network or ip you want to scan|/")
op=p.parse_args()[0]
try:
    nds(op.ip_address)
except KeyboardInterrupt:
    print("bye bye")
