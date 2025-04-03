import scapy; import socket
class main:

    def ping_target(ip):
        ip = scapy.IP(dst=ip)
        icmp =scapy.ICMP()
        packet = ip/icmp
        response = scapy.sr1(packet,timeout=1)
        if response:
            print(f"[+] The host {ip} is up.\n")
        else:
            print(f"[-] The host {ip} is down.\n")

    def scan_tcp(ip, self, port):
        ip = scapy.IP(dst=ip)
        syn = scapy.TCP(dport=port, flasg="S")
        packet = ip/syn
        response = scapy.sr1(packet, timeout=1, verbose=0)
        if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            return(port, "open")
        elif response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x14:
            return(port, "close")
        else:
            return(port, "refused")

class ip:

    def host_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8',1))
            host_ip = s.getsockname()[0]
        except Exception:
            host_ip = "No se pudo obtener la dirección ip"
        finally:
            s.close()
        return host_ip
    
    def network_ip():
        host_ip = ip.host_ip()
        network_ip = host_ip.split(".")
        network_ip.pop()
        network_ip = ".".join(network_ip)
        return network_ip
        

"""
scanner = main()
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
ip_red = host_ip.split(".")
ip_red.pop()
ip_red = ".".join(ip_red)
print(f"host name {host_name}")
print(f"Host ip {host_ip}")
print(f"Ip {ip_red}")
"""
search = ip()
host_ip = ip.host_ip()
print(host_ip)
network_ip = ip.network_ip()
print(network_ip)

def search_host():
    for i in 255:
        main.ping_target()
    