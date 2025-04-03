import socket
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf, TCP, UDP; import os

conf.verb = 0


if os.getuid() != 0:
    print("[!] You need to run this script as root.")
    exit(1)

class tool():

    def host_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            self.host_ip = s.getsockname()[0]
        except Exception:
            print("No internet connection.")
            self.host_ip = None
        finally:
            s.close()
            return self.host_ip

    def network_ip(self):
        ip = self.host_ip.split('.')
        ip.pop()
        network_ip = '.'.join(ip)
        return network_ip

    def arp_scan(self, ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether / arp
        try:
            response = srp(packet, timeout=1, verbose=False)[0]
            if response:
                for sent, received in response:
                    return received.psrc, received.hwsrc
            else:
                return None 
        except Exception as e:
            return "error",e

    def icmp_scan(self, ip):
        packet_ip = IP(dst=ip)
        packet_icmp = ICMP()
        packet = packet_ip / packet_icmp
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            return ip
        else:
            return None

    def tcp_scan(self, ip, port):
        packet_ip = IP(dst=ip)
        protocol = TCP(dport=port, flags='S')
        packet = packet_ip / protocol
        response = sr1(packet, timeout=1, verbose=False)
        if response.haslayer(TCP) and response[TCP].flags == 0x12:
            return ip and port
        else:
            return False
    
    def udp_scan(self, ip, port):
        packet_ip = IP(dst=ip)
        protocol = UDP(dport=port)
        packet = packet_ip / protocol
        response = sr1(packet, timeout=2, verbose=False)
        if response is None:
            return("open or filtered")
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                return False
            elif icmp_type == 3 and icmp_code == 1:
                return(port, icmp_type, icmp_code)
        elif response.haslayer(UDP):
            return True
        else:
            return None
    
    def search_os(self, ip):
        packet_ip = IP(dst=ip)
        protocol = TCP()
        packet = packet_ip / protocol
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            ttl = response[IP].ttl
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "MacOS or Cisco/Network Device"
        return "Not found"
    


scaner = tool()
print("IP del host:", scaner.host_ip())
print("IP de la red:", scaner.network_ip())
print(scaner.arp_scan("192.168.1.1"))
print(scaner.icmp_scan("192.168.1.1"))