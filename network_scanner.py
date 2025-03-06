#!/usr/bin/env python3

import netifaces
import ipaddress
import socket
from scapy.all import ARP, Ether, srp

def get_local_subnet():

    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                local_ip = ip_info['addr']
                subnet_mask = ip_info['netmask']

                if local_ip.startswith("127."):
                    continue

                network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                return str(network)
        except (ValueError, KeyError):
            continue
    return None

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    answered, unanswered = srp(packet, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    return devices

def scan_ports(ip, ports=[22, 80, 443, 3389]):

    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

network_range = get_local_subnet()
if network_range is None:
    print("Could not detect local network. Please check your network connection.")
else:
    print(f"Scanning network: {network_range}")

    devices_found = scan_network(network_range)

    print("\nActive Devices:")
    print("IP Address\t\tMAC Address\t\tOpen Ports")
    print("-" * 60)
    for device in devices_found:
        open_ports = scan_ports(device['IP'])
        print(f"{device['IP']}\t\t{device['MAC']}\t\t{', '.join(map(str, open_ports)) if open_ports else 'None'}")