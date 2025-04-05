#Code by Donne

#Libs
import socket
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf, TCP, UDP

#Why is that here?
among_us = """
⠀⠀⠀⣠⣤⠶⠶⢖⣦⠀⠀⣴⠀⠀⠀⢠⡀⠀⠀⠀⢀⣶⠟⠛⠒⢦⡀⠀⠀⠀⣿⡇⠀⠀⣠⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣯⡹⡄⠀⠀⠘⡾⠀⢠⡿⠀⠀⠀⢸⣷⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⣠⡟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⠿⣷⡄⠀⢸⡇⠀⠀⠀⣾⡏⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣤⡀⠀⠀⠀⣼⠁⠀⢸⣧⠀⠀⠀⣿⡇⠀⠀⠱⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⡇⠙⣷⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠉⠻⠭⠋⠁⠀⠀⠀⠻⠿⣿⠏⠁⠀⠀⠀⠀⠱⣟⣦⣀⡠⣖⡇⠀⠀⠀⣿⡇⠀⠀⠀⠙⠯⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡆⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡠⠤⠤⠤⠤⣀⡀⠀⠀⠀⠀⠀⢠⣿⢹⡇⠀⠀⠀⡟⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⠔⠋⠉⠉⠉⢦⣠⠎⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢦⠀⠀⠀⢸⣿⠀⠹⡆⡠⡏⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⠃⠀⠀⠀⠀⠀⡐⠁⠀⠀⠀⢀⡖⠊⠉⠉⠉⠉⠉⠉⠉⠓⣧⠀⠀⣿⣿⠀⠀⣳⡏⠀⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⠇⠀⠀⠀⠀⠀⡜⠁⠀⠀⠀⠀⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡇⠀⠸⣿⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡜⠀⠀⠀⠀⠀⢠⠁⠀⠀⠀⠀⠀⠀⠓⢤⡀⠀⠀⠀⠀⠀⠀⢀⡞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢇⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠒⠋⠉⠀⡇⠀⠀⠀⢻⣆⠀⠀⠀⠀⣴⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠳⣄⡀⠀⣠⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠉⢿⡆⣖⡏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⢀⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⡰⠋⢹⡀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⣠⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⡞⠀⠀⠀⢧⡀⠀⠀⠀⠀⢀⡏⠀⠀⠾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣶⡖⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡟⡏⠻⢷⣄⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⣷⣇⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⣼⡏⠁⠉⠉⠻⣷⡄⠀⠀⠀⠀
⠀⠀⠀⡿⡇⠀⠀⣸⡇⠀⠀⠀⣞⡏⠈⣿⡄⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠈⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⡷⠾⠯⣏⠀⠀⠀⣼⡟⠀⠀⠈⣇⠀⠀⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠈⠯⣓⣶⡶⠶⣶⡦⡀⠀⠀⠀
⠀⠀⠀⡟⡇⠀⠀⠈⢻⠀⣼⡿⠿⠿⠿⠿⢿⡆⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⣿⡆⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⡾⡇⠀⠀⠀
⠀⠀⠀⠿⢤⣤⣄⡴⠃⠀⡟⠀⠀⠀⠀⠀⠀⠿⠀⠀⠸⠿⠷⣶⣶⣶⣶⡦⠀⠀⠿⣶⣷⣶⣖⣟⠷⠀⠀⠈⠷⣤⣤⣤⣴⡟⠁⠀⠀⠀
"""


#Scanner
class scanner:
    def __init__(self):
        self.timeout_val = 1

    """IP FUNCIONS"""
    #Get the local IP address
    def get_host_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout_val)
        try:
            s.connect(('8.8.8.8', 1))
            self.host_ip = s.getsockname()[0]
            return {'ip': self.host_ip, 'status': 'success', 'error': None}
        except Exception as e:
            return {'ip': None, 'status': 'error', 'error': str(e)}
        finally:
            s.close()

    #Get Subnet
    def get_subnet(self):
        #check ip
        self.host_ip = self.get_host_ip()
        if self.host_ip['status'] == 'error':
            return {'subnet': None, 'status': 'error', 'error': self.host_ip['error']}
        else:
            ip = self.host_ip['ip']
        self.subnet = self.split_ip(ip)
        return {'subnet': self.subnet, 'status': 'success', 'error': None}

    #Split the ip address
    def split_ip(self, ip):
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            return False
        for part in ip_parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False
        del ip_parts[3]
        ip = '.'.join(ip_parts)
        return ip

    #Take last part of ip
    def pop_ip(self, ip):
        octet = ip.split('.')
        if len(octet) == 4:
            return octet[-1] 
        else:
            raise ValueError("[!] Invalid IP.")
    
    #Ip validation
    def ip_validation(self, ip):
        if self.split_ip(ip) == self.subnet:
            return True
        return False

    """SCAN FUNCIONS"""
    #ARP Scan
    def arp_scan(self, ip):
        try:
            packet_ip = ARP(pdst=ip)
            ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ethernet / packet_ip
            response = srp(packet, timeout=self.timeout_val, verbose=0)[0]
            if response:
                for sent, received in response:
                    return {'ip': ip, 'mac': received.hwsrc, 'status': 'up', 'error': None}
            else:
                return {'ip': ip, 'mac': 'unknown', 'status': 'down', 'error': None}
        except Exception as e:
            return {'clients': None, 'status': 'error', 'error': str(e)}
    
    #ICMP Scan
    def icmp_scan(self, ip):
        try:
            packet_ip = IP(dst=ip)
            icmp = ICMP()
            packet = packet_ip / icmp
            response = sr1(packet, timeout=self.timeout_val, verbose=0)
            if response:
                return{'ip': ip, 'status': 'up', 'error': None}
            else:
                return {'ip': ip, 'status': 'down', 'error': None}
        except Exception as e:
            return {'ip': ip, 'status': 'error', 'error': str(e)}
    
    #TCP Scan
    def tcp_scan(self, ip, port):
        try:
            packet_ip = IP(dst=ip)
            protocol = TCP(dport=port, flags='S')
            packet = packet_ip / protocol
            response = sr1(packet, timeout=self.timeout_val, verbose=0)
            if response:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        return {'ip': ip, 'port': port, 'status': 'open', 'error': None}
                    elif response.getlayer(TCP).flags == 0x14:
                        return {'ip': ip, 'port': port, 'status': 'closed', 'error': None}
            else:
                return {'ip': ip, 'port': port, 'status': 'filtered', 'error': None}
        except Exception as e:
            return {'ip': ip, 'port': port, 'status': 'error', 'error': str(e)}
    
    #UDP Scan
    def udp_scan(self, ip, port):
        try:
            packet_ip = IP(dst=ip)
            protocol = UDP(dport=port)
            packet = packet_ip / protocol
            response = sr1(packet, timeout=self.timeout_val, verbose=0)
            if response:
                if response.haslayer(UDP):
                    return {'ip': ip, 'port': port, 'status': 'open', 'error': None}
                else:
                    return {'ip': ip, 'port': port, 'status': 'closed', 'error': None}
            else:
                return {'ip': ip, 'port': port, 'status': 'filtered', 'error': None}
        except Exception as e:
            return {'ip': ip, 'port': port, 'status': 'error', 'error': str(e)}
    
    #OS ttl scan
    def os_ttl_scan(self, ip):
        try:
            packet_ip = IP(dst=ip)
            protocol = TCP()
            packet = packet_ip / protocol
            response = sr1(packet, timeout=self.timeout_val, verbose=0)
            if response:
                ttl = response[IP].ttl
                if ttl <= 64:
                    return{'ip': ip, 'os': 'Linux', 'error': None}
                if ttl <= 128:
                    return{'ip': ip, 'os': 'Windos', 'error': None}
                if ttl <= 255:
                    return{'ip': ip, 'os': None, 'error': None}
        except Exception as e:
            return {'ip': ip, 'os': None, 'error': str(e)}
        