import sys
import time
from scapy.all import Ether, IP, TCP, send, sr1,ICMP
import random

open_ports = []

def port_randomizer():
    return random.randint(1,5000)

def send_packets(target_ip, num_packets, duration, open_port):
    end_time = time.time() + duration
    packet_count = 0

    while time.time() < end_time and packet_count < num_packets:
        packet = IP(dst=target_ip) / TCP(dport=open_port, flags="S")
        send(packet, verbose=0)
        print(f"Sent SYN to port {open_port}")
        packet_count += 1

def main():

    send(IP(dst="192.168.1.183") / ICMP(), verbose=1)
    send_packets("192.168.1.183",10,1,445)

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)
        
    main()

    #send_packets(TARGET_IP,INTERFACE,NUM_PACKETS,DURATION, port_randomizer())
    #send_packets_random(TARGET_IP,INTERFACE,NUM_PACKETS,DURATION)
