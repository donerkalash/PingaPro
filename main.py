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
        #craft scaner
        self.scaner = scanner.scanner()
        #take ip host
        self.scaner.get_host_ip()
        self.scaner.get_subnet()


    """Scan one host"""
    def single_host_scan(self, ip, mode):

        if self.scaner.ip_validation(ip):
            #arp_single_scan
            if mode == 'arp':
                result = self.scaner.arp_scan(ip)
                if result:
                    print(f"* Host {ip} is {result['status']} with mac {result['mac']}")
            #arp_single_scan
            elif mode == 'icmp':
                result = self.scaner.icmp_scan(ip)
                print(f"* Host {ip} is {result['status']}.")
            return result
        else:
            print("[!] The ip address entered is invalid")


    """Range host scan"""
    def range_host_scan(self, ip1, ip2, mode):

        #pop ip to craft ip for scan
        ip_scan1 = int(self.scaner.pop_ip(ip1))
        ip_scan2 = int(self.scaner.pop_ip(ip2))
        print(f"[+] Scanning from {ip1} to {ip2}...")
        discovered_host = 0

        #arp_range_scan
        if mode == 'arp':
            for i in  range(ip_scan1, ip_scan2):
                #craft ip
                ip = self.scaner.subnet+"."+str(i)
                #scan ip
                result = self.scaner.arp_scan(ip)
                if result['status'] == 'up':
                    print(f"* New host discovered {result['ip']} with mac {result['mac']}")
                    discovered_host += 1
        #icmp_range_scan
        elif mode == 'icmp':
            for i in range(ip_scan1, ip_scan2):
                #craft ip
                ip = self.scaner.subnet+"."+str(i)
                #scan ip
                result = self.scaner.arp_scan(ip)
                if result['status'] == 'up':
                    print(f"* New host discovered {result['ip']}.")
                    discovered_host += 1

        #results_count
        if discovered_host == 0:
            print(f"[!] No active host found between {ip1} and {ip2}.")
        else:
            print(f"[+] Have been discovered {discovered_host} host.")                


    """Scan all net"""
    def all_host_scan(self, mode):

        print(f"[+] Scanning the whole network...")
        discovered_host = 0
        
        if mode == 'arp':
            for i in range(1,255):
                ip = self.scaner.subnet+"."+str(i)
                result = self.scaner.arp_scan(ip)
                if result['status'] == 'up':   
                    print(f"* New host discovered {result['ip']} with mac {result['mac']}")
                    discovered_host += 1
        elif mode == 'icmp':
            for i in range(1,255):
                ip = self.scaner.subnet+"."+str(i)
                result = self.scaner.arp_scan(ip)
                if result['status'] == 'up':
                    print(f"* New host discovered {result['ip']}")
                    discovered_host += 1
            
        #result_count
        if discovered_host == 0:
            print(f"[!] No active host found in the whole network.")
        else:
            print(f"[+] Have been discovered {discovered_host} host")
           

        """One port scan"""
    def single_port_scan(self, mode, ip, port):
        if mode == 'tcp':
            result = self.scaner.tcp_scan(ip, port)
            print(f"* The port {result['port']} on {result['ip']} is {result['result']}.")



menu = scanner_manu()
