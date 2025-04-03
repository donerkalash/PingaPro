import socket; from scapy.all import IP, ICMP, TCP, sr1, conf, ARP , Ether, srp; import os 

vrb = True

if os.getuid() != 0:
    print("You need to run this script as root.")
    exit(1)

class scanner:

    def __init__(self):
        def __init__(self):
            self.vrb = True

    def host_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            host_ip = s.getsockname()[0]
        except Exception:
            if vrb == True:
                print("[!] No se ha encontrado conexión a Internet.")
            host_ip = None
        finally:
            s.close()
        return host_ip

    def network_ip():
        network_ip = scanner.host_ip().split('.')
        network_ip.pop()
        network_ip = '.'.join(network_ip)
        return network_ip
    
    def arp_scan(ip):
        packet_arp = ARP(pdst=ip)
        packet_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = packet_broadcast / packet_arp
        answered_list = srp(packet, timeout=1, verbose=False)[0]
        for i in answered_list:
            return i[1].hwsrc #return mac 
        return None


    def ping(ip):
        mac = scanner.mac(ip)
        if mac is None:
            return False
        else:
            packet_ip = IP(dst=ip)
            packet_icmp = ICMP()
            packet = packet_ip / packet_icmp
            response = sr1(packet, timeout=1, verbose=False)
            if response is None:
                return False
            else:
                return True
    
    def port_scan(ip, port):
        packet_ip = IP(dst=ip)
        packet_tcp = TCP(dport=port, flags="S")
        packet = packet_ip / packet_tcp
        response = sr1(packet, timeout=1, verbose=False)
        if response.haslayer(TCP) and response[TCP].flags == 0x12:
            return True
        else:
            return False
        
    def verbose():
        global vrb
        if vrb == True:
            vrb = False
            return False
        else:
            vrb = True
            return True

class main(scanner):
    def arp_scan():
        network_ip = scanner.network_ip()
        hosts = []
        for i in range(1, 255):
            ip = f"{network_ip}.{i}"
            if scanner.arp_scan(ip):
                hosts.append(ip)
                if vrb == True:
                    print(f"[+] Host found: {ip}\n")
        return hosts

b = main.search_hosts()
print(b)