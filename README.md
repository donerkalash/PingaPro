Network Scanner Tool

This Python script provides a network scanning tool for network administrators and security professionals. It offers several functions such as ARP scanning, ICMP (ping) scanning, TCP and UDP port scanning, and OS detection based on TTL values.
Features

    Network IP Detection: Automatically detects the local network IP.

    ARP Scan: Discovers devices on the local network using ARP.

    ICMP Scan: Pings devices to determine if they are online.

    TCP Scan: Scans a device for open TCP ports.

    UDP Scan: Scans a device for open UDP ports.

    OS Detection: Attempts to detect the operating system based on the TTL value of responses.

Prerequisites

Before running this script, ensure the following:

    Python 3.x is installed.

    Scapy library is installed for network packet manipulation.

    You can install Scapy using pip:

    pip install scapy

    The script needs to be run with root privileges as it requires access to raw sockets.

How to Use

    Run the script as root:

    sudo python3 network_scanner.py

    Once running, the script will display a menu with the following options:

        Get Network IP: Display the network's IP address.

        ARP Scan: Perform an ARP scan to discover devices on the network.

        ICMP Scan: Perform a ping sweep to detect active hosts.

        TCP Scan: Scan for open TCP ports on a specified host.

        UDP Scan: Scan for open UDP ports on a specified host.

        OS Detection: Detect the operating system of a host based on the TTL value.

        Exit: Quit the program.

Example Workflow

    ARP Scan: You can scan your local network to find devices connected to it. Enter the IP address of the device or leave it blank to scan the entire local network.

    TCP Scan: Scan specific ports on a host to check if they are open. You can specify a port or scan all ports.

    UDP Scan: Similar to TCP Scan but for UDP ports.

    OS Detection: Try to determine the operating system of a host based on the TTL value of the response.

Code Explanation
Tool Class

This class contains methods for performing various network scans:

    host_ip(): Retrieves the local IP address of the machine running the script.

    network_ip(): Retrieves the network IP (without the last octet).

    arp_scan(ip): Performs an ARP scan on the provided IP address or network.

    icmp_scan(ip): Pings the provided IP to check if it’s active.

    tcp_scan(ip, port): Scans a specific TCP port on the given IP.

    udp_scan(ip, port): Scans a specific UDP port on the given IP.

    search_os(ip): Attempts to detect the operating system by analyzing the TTL of a response.

Menu Class

The menu-driven interface lets the user interact with the tool. Each method corresponds to one of the available options:

    get_network_ip(): Displays the network's IP.

    arp_scan(): Calls arp_scan() to discover hosts on the network.

    icmp_scan(): Calls icmp_scan() to check if a host is active.

    tcp_scan(): Calls tcp_scan() to check for open TCP ports.

    udp_scan(): Calls udp_scan() to check for open UDP ports.

    os_detection(): Calls search_os() to attempt OS detection.

Example of Running the Program

$ sudo python3 network_scanner.py

Note

    Ensure you have appropriate permissions when running network scans, especially in a production environment.

    This tool is intended for educational purposes and should be used responsibly.

License

This tool is provided under the MIT License. See the LICENSE file for details.