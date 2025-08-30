import sys
import time
from scapy.all import Ether, IP, TCP, sendp, sr1
import random

TARGET_IP = "192.168.1.183"
INTERFACE = "Wi-Fi"
NUM_PACKETS = 10
DURATION = 1

open_ports = []

def port_randomizer():
    return random.randint(1,5000)

def send_packets(target_ip, interface, num_packets, duration, open_port):
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        packet = Ether() / IP(dst=target_ip) / TCP(dport=open_port, flags="S")
        sendp(packet, iface=interface)
        print(f"Port = {open_port}")
        packet_count += 1
        
def send_packets_random(target_ip, interface, num_packets, duration):
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        port = random.randint(1,5000)
        packet = Ether() / IP(dst=target_ip) / TCP(dport=port, flags="S")
        sendp(packet, iface=interface)
        print(f"Port = {port}")
        packet_count += 1

def main():

    send_packets_random(TARGET_IP,INTERFACE,NUM_PACKETS,DURATION)

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)
        
    main()

    #send_packets(TARGET_IP,INTERFACE,NUM_PACKETS,DURATION, port_randomizer())
    #send_packets_random(TARGET_IP,INTERFACE,NUM_PACKETS,DURATION)
