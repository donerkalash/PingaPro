#Libs
import scanner
import socket
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf, TCP, UDP
import os

#Check if the script is running as root
if os.getuid() != 0:
    print("[!] Please run this script as root.")
    exit(1)

#Check if scapy is installed
try:
    from scapy.all import *
except ImportError:
    print("[!] Scapy is not installed. Please install it using 'pip install scapy'")
    exit(1)

#Check if the script is running on Linux
if os.name != 'posix':
    print("[!] This script is only compatible with Linux.")
    exit(1)


class scanner_manu():
    def __init__(self):
        self.scaner = scanner.scanner()
        self.scaner.get_host_ip()

    def show_subnet(self):
        subnet = self.scaner.get_subnet()
        return subnet
    
    def single_arp_scan(self, ip):
        if self.scaner.ip_validation(ip):
            result = self.scaner.arp_scan(ip)
            print(f"* Host {ip} is {result['status']}.")
            return result


    def range_arp_scan(self, ip1, ip2):
        if not self.scaner.subnet:
            self.scaner.get_subnet
        ip_scan1 = int(self.scaner.pop_ip(ip1))
        ip_scan2 = int(self.scaner.pop_ip(ip2))
        discovered_host = 0
        print(f"[+] Scanning from {ip1} to {ip2}...")
        for i in range(ip_scan1, ip_scan2):
            ip = self.scaner.subnet+"."+str(i)
            result = self.scaner.arp_scan(ip)
            if result['status'] == 'up':         
                print(f"* New host discovered {ip} with mac {result['mac']}")
                discovered_host =+ 1
        if discovered_host == 0:
            print(f"[!] No active host found between {ip1} and {ip2}.")
        else:
            print(f"[+] Have been discovered {discovered_host} host")

    def all_arp_scan(self):
        print(f"[+] Scanning the whole network...")
        discovered_host = 0
        if not self.scaner.subnet:
            self.scaner.get_subnet
        for i in range(1,255):
            ip = self.scaner.subnet+"."+str(i)
            result = self.scaner.arp_scan(ip)
            if result['status'] == 'up':   
                print(f"* New host discovered {ip} with mac {result['mac']}")
                discovered_host = discovered_host + 1
        if discovered_host == 0:
            print(f"[!] No active host found in the whole network.")
        else:
            print(f"[+] Have been discovered {discovered_host} host")


    

    
    

menu = scanner_manu()
menu.show_subnet()
menu.single_arp_scan('192.168.1.136')
#menu.range_arp_scan('192.168.1.135','192.168.1.137')
menu.all_arp_scan()
        