#!/usr/bin/env python
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) #create ip packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # create ethernet packet
    arp_request_broadcast = broadcast/arp_request #combine together the packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose="False")[0] #send the packet and receive the response
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
