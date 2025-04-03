import socket
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf, TCP, UDP
import os

conf.verb = 0

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

# Check if the script is running as root
if os.getuid() != 0:
    print("[!] You need to run this script as root.")
    exit(1)

class Tool():

    def host_ip(self):
        """Gets the host's IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            self.host_ip = s.getsockname()[0]
            return {"ip": self.host_ip, "status": "success", "error": None}
        except Exception as e:
            return {"ip": None, "status": "error", "error": str(e)}
        finally:
            s.close()

    def network_ip(self):
        """Gets the local network IP."""
        try:
            host_ip_result = self.host_ip()  # Call the instance method
            if host_ip_result["status"] == "error" or host_ip_result["ip"] is None:
                return {"network_ip": None, "status": "error", "error": host_ip_result["error"]}
            ip = host_ip_result["ip"]
            if ip is None:
                return {"network_ip": None, "status": "error", "error": "Host IP is None"}
            ip_parts = ip.split('.')
            ip_parts.pop()
            self.network_ip = '.'.join(ip_parts)
            return {"network_ip": self.network_ip, "status": "success", "error": None}
        except Exception as e:
            return {"network_ip": None, "status": "error", "error": str(e)}

    def arp_scan(self, ip):
        """Performs an ARP scan on the local network."""
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            packet = ether / arp
            response = srp(packet, timeout=1, verbose=False)[0]
            if response:
                for sent, received in response:
                    return {"ip": received.psrc, "mac": received.hwsrc, "status": "success", "error": None}
            else:
                return {"ip": ip, "mac": None, "status": "no_response", "error": None}
        except Exception as e:
            return {"ip": ip, "mac": None, "status": "error", "error": str(e)}

    def icmp_scan(self, ip):
        """Performs an ICMP (ping) scan to check if a host is active."""
        try:
            packet_ip = IP(dst=ip)
            packet_icmp = ICMP()
            packet = packet_ip / packet_icmp
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                return {"ip": ip, "status": "active", "error": None}
            else:
                return {"ip": ip, "status": "inactive", "error": None}
        except Exception as e:
            return {"ip": ip, "status": "error", "error": str(e)}

    def tcp_scan(self, ip, port):
        """Performs a TCP scan on a specific port."""
        try:
            packet_ip = IP(dst=ip)
            protocol = TCP(dport=port, flags='S')
            packet = packet_ip / protocol
            response = sr1(packet, timeout=1, verbose=False)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                return {"ip": ip, "port": port, "status": "open", "error": None}
            else:
                return {"ip": ip, "port": port, "status": "closed", "error": None}
        except Exception as e:
            return {"ip": ip, "port": port, "status": "error", "error": str(e)}

    def udp_scan(self, ip, port):
        """Performs a UDP scan on a specific port."""
        try:
            packet_ip = IP(dst=ip)
            protocol = UDP(dport=port)
            packet = packet_ip / protocol
            response = sr1(packet, timeout=2, verbose=False)
            if response is None:
                return {"ip": ip, "port": port, "status": "open_or_filtered", "error": None}
            elif response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                if icmp_type == 3 and icmp_code == 3:
                    return {"ip": ip, "port": port, "status": "closed", "error": None}
                else:
                    return {"ip": ip, "port": port, "status": f"ICMP type {icmp_type} code {icmp_code}", "error": None}
            elif response.haslayer(UDP):
                return {"ip": ip, "port": port, "status": "open", "error": None}
            else:
                return {"ip": ip, "port": port, "status": "unknown", "error": None}
        except Exception as e:
            return {"ip": ip, "port": port, "status": "error", "error": str(e)}

    def search_os(self, ip):
        """Attempts to detect the operating system based on the TTL."""
        try:
            packet_ip = IP(dst=ip)
            protocol = TCP()
            packet = packet_ip / protocol
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                ttl = response[IP].ttl
                if ttl <= 64:
                    return {"ip": ip, "os": "Linux", "error": None}
                elif ttl <= 128:
                    return {"ip": ip, "os": "Windows", "error": None}
                elif ttl <= 255:
                    return {"ip": ip, "os": "MacOS or Cisco/Network Device", "error": None}
            return {"ip": ip, "os": "unknown", "error": None}
        except Exception as e:
            return {"ip": ip, "os": None, "error": str(e)}

class Menu:
    # Assets
    banner = """
 ██▓███   ██▓ ███▄    █   ▄████  ▄▄▄          ██▓███   ██▀███   ▒█████    
▓██░  ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒▒████▄       ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒
▓██░ ██▓▒▒██▒▓██  ▀█ ██▒▒██░▄▄▄░▒██  ▀█▄     ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒
▒██▄█▓▒ ▒░██░▓██▒  ▐▌██▒░▓█  ██▓░██▄▄▄▄██    ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░
▒██▒ ░  ░░██░▒██░   ▓██░░▒▓███▀▒ ▓█   ▓██▒   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░
▒▓▒░ ░  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░   ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ 
░▒ ░      ▒ ░░ ░░   ░ ▒░  ░   ░   ▒   ▒▒ ░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ 
░░        ▒ ░   ░   ░ ░ ░ ░   ░   ░   ▒      ░░         ░░   ░ ░ ░ ░ ▒  
          ░           ░       ░       ░  ░               ░         ░ ░  
                                                                        
"""
    options = ("""
Select an option:

* Get Network IP -----> 1
* ARP Scan -----------> 2
* ICMP Scan ----------> 3
* TCP Scan -----------> 4
* UDP Scan -----------> 5
* OS Detection -------> 6
* Exit ---------------> 7

Input: """)

    def __init__(self, scanner):
        """Initialize the menu with a scanner instance."""
        self.scanner = scanner  # Store the Tool instance
        self.network_info = self.scanner.network_ip()  # Get network IP info

    def clear(self):
        """Clear the console and print the banner."""
        os.system("clear")
        print(self.banner)

    def menu(self):
        """Display the menu and handle user input."""
        while True:
            self.clear()
            selection = input(self.options)

            if selection == "1":
                self.get_network_ip()
            elif selection == "2":
                self.arp_scan()
            elif selection == "3":
                self.icmp_scan()
            elif selection == "4":
                self.tcp_scan()
            elif selection == "5":
                self.udp_scan()
            elif selection == "6":
                self.os_detection()
            elif selection == "7":
                os.system("clear")
                input(among_us)
                break
            else:
                print("Invalid option. Please try again.")

    def get_network_ip(self):
        """Display the network IP information."""
        self.clear()
        if self.network_info['status'] == "error":
            print(f"Error: {self.network_info['error']}")
            input("\nPress Enter to return to the menu...")
            return
        print("Network IP -> ", self.network_info['network_ip'])
        input("\nPress Enter to return to the menu...")

    def arp_scan(self):
        """Perform an ARP scan."""
        self.clear()
        ip = input("Enter IP to scan or leave blank to scan the entire network:\n-> ")
        self.clear()
        try:
            if ip == "":
                print("\n[!] Scanning the entire network...\n")
                for i in range(1,255):
                    ip = f"{self.network_info['network_ip']}.{i}"
                    results = self.scanner.arp_scan(ip)
                    ip = results['ip']
                    mac = results['mac']
                    status = results['status']
                    if status == "success":
                        print(f"\n[+] New Host Found:\nIP  -> {ip}\nMAC -> {mac}\n")
                    elif status == "no_response":
                        pass
                    elif status == "error":
                        print(f"\n[!] Error: {results['error']}")
            else:
                ip_probe = ip.split(".")
                ip_probe.pop()
                ip_probe = '.'.join(ip_probe)
                if ip_probe == self.network_info['network_ip']:
                    print("\n[!] Scanning the entire network...\n")
                    results = self.scanner.arp_scan(ip)
                    ip = results['ip']
                    mac = results['mac']
                    status = results['status']
                    self.clear()
                    if status == "success":
                        print(f"IP: {ip}\nMAC: {mac}")
                    elif status == "no_response":
                        print(f"No response from {ip}.")
                    else:
                        print(f"Error: {results['error']}")
                    input("\nPress Enter to return to the menu...")
                else:
                    print("\n[!] Invalid IP address.")
                    input("\nPress Enter to return to the menu...")
        except Exception as e:
            print(f"Error: {e}")
            input("\nPress Enter to return to the menu...")

    def icmp_scan(self):
        """Perform an ICMP scan."""
        self.clear()
        ip = input("Enter the IP to scan:\n-> ")
        self.clear()
        if ip == "":
            print("\n[!] Scanning the entire network...\n")
            for i in range(1, 255):
                ip = f"{self.network_info['network_ip']}.{i}"
                result = self.scanner.icmp_scan(ip)
                if result['status'] == "active":
                    print(f"\n[+] New Host Found:\nIP -> {ip}")
        ip_probe = ip.split(".")
        ip_probe.pop()
        ip_probe = '.'.join(ip_probe)
        if ip_probe == self.network_info['network_ip']:
            print("\n[!] Scanning the ip...\n")
            result = self.scanner.icmp_scan(ip)
            self.clear()
            if result['status'] == "active":
                print(f"IP: {ip}\nStatus: {result['status']}")
                input("\nPress Enter to return to the menu...")
            else:
                print(f"No response from {ip}.")
                input("\nPress Enter to return to the menu...")
        else:
            print("\n[!] Invalid IP address.")
            input("\nPress Enter to return to the menu...")
            return

    def tcp_scan(self):
        """Perform a TCP scan."""
        self.clear()
        ip = input("Enter the IP to scan:\n-> ")
        ip_probe = ip.split(".")
        ip_probe.pop()
        ip_probe = '.'.join(ip_probe)
        if ip_probe != self.network_info['network_ip']:
            print("\n[!] Invalid IP address.")
            input("\nPress Enter to return to the menu...")
            return
        self.clear()
        port = input("Enter the port to scan or leave blank to scan all ports:\n-> ")
        self.clear()
        if port == "":
            print(f"\n[!] Scanning all ports of {ip}...\n")
            for i in range(1, 65535):
                result = self.scanner.tcp_scan(ip, i)
                if result['status'] == "open":
                    print(f"\nPort -> {i} OPEN")
                if result['status'] == "closed":
                    pass
                if result['status'] == "error":
                    print(f"Error: {result['error']}")                   
        else:
            print("\n[!] Scanning the specified port...\n")
            port = int(port)
        result = self.scanner.tcp_scan(ip, port)
        print(f"IP: {ip}\nPort: {port}\nStatus: {result['status']}")
        input("\nPress Enter to return to the menu...")

    def udp_scan(self):
        """Perform a UDP scan."""
        self.clear()
        ip = input("Enter the IP to scan or leave blank to scan all ports:\n-> ")
        self.clear()
        if ip == "":
            print(f"\n[!] Scanning  all ports of {ip}...\n")
            for i in range(1, 65535):
                result = self.scanner.udp_scan(ip, i)
                if result['status'] == "open":
                    print(f"\nPort -> {i} OPEN")
                if result['status'] == "closed":
                    pass
                if result['status'] == "error":
                    print(f"Error: {result['error']}")
        ip_probe = ip.split(".")
        ip_probe.pop()
        ip_probe = '.'.join(ip_probe)
        if ip_probe != self.network_info['network_ip']:
            print("\n[!] Invalid IP address.")
            input("\nPress Enter to return to the menu...")
            return
        else:
                print("\n[!] Scanning the ip...\n")
                result = self.scanner.udp_scan(ip, 0)
                self.clear()
                print(f"IP: {ip}\nPort: {port}\nStatus: {result['status']}")
                input("\nPress Enter to return to the menu...")


        
        port = int(input("Enter the port to scan:\n-> "))
        result = self.scanner.udp_scan(ip, port)
        print("UDP Scan Result:")
        print(result)
        input("\nPress Enter to return to the menu...")

    def os_detection(self):
        """Perform OS detection."""
        self.clear()
        ip = input("Enter the IP to detect the OS:\n-> ")
        result = self.scanner.search_os(ip)
        print("OS Detection Result:")
        print(result)
        input("\nPress Enter to return to the menu...")

# Script execution
scanner = Tool()
menu = Menu(scanner)
menu.menu()