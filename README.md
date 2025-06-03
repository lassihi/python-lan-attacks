# Python-lan-attacks

Python Scapy scripts for various LAN attacks. These scripts were made in order to learn about packet manipulation with Scapy and LAN vulnerabilities.

All scripts require [Scapy](https://scapy.net/) Python module.

## dhcp_starvation.py

Leases all available IPv4 addresses on the network for random MAC addresses.

Usage: `sudo python3 dhcp_starvation.py`

## arp_poison.py

Poisons the ARP cache of target host by sending spoofed ARP messages. Spoofed ARP messages contain spoofed IP address along with the attacker's (your) MAC address.

Usage: `sudo python3 arp_poison.py <target_ip> <spoofed_ip>`

## mitm.py

Relays spoofed packets (with `arp_poison.py`) to the correct destination.

Usage: `sudo python3 mitm.py <host_1> <host_2>`

Example MITM attack using `arp_poison.py` and `mitm.py`, while `192.168.1.113` is pinging `192.168.1.109`.

<img width="960" alt="image" src="https://github.com/user-attachments/assets/807ab2cf-3870-417e-9278-11f4184e54f0" />

