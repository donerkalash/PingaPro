import socket
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf

conf.verb = 0

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
        response = srp(packet, timeout=1, verbose=False)[0]
        if response:
            for sent, received in response:
                result = (received.psrc, received.hwsrc)
                return result
        else:
            return None

    def icmp_scan(self, ip):
        packet_ip = IP(dst=ip)
        packet_icmp = ICMP()
        packet = packet_ip / packet_icmp
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            return ip
        else:
            return False
    

scaner = tool()
print("IP del host:", scaner.host_ip())
print("IP de la red:", scaner.network_ip())
print(scaner.arp_scan("192.168.1.1"))
print(scaner.icmp_scan("192.168.1.1"))