"""
DISCLAIMER: This program is intended for educational purposes only. It must NOT be used maliciously
for activities such as probing, flooding, scanning, or any unauthorized network access. Always use
this tool within a controlled environment such as a private lab network or virtual environment.

This program is a basic packet crafter that supports TCP and UDP protocols. It allows sending packets
with a specified destination MAC address for Layer 2 traffic, as well as destination IPv4 addresses
for Layer 3 traffic. It also supports crafting packets with spoofed source IPv4 addresses and source ports.

Author: Noah Cosamano
"""

from scapy.all import TCP,sr1,sr,srp1,srp,send,sendp,IP,UDP,Ether,ICMP

class Packet:
    __slots__ = ["dst_ip","dst_mac","protocol","dst_port","flags","src_port","src_ip"]
    
    def __init__(self,dst_ip:str,protocol:str,dst_port:int,flags:str|list|None=None,
                 dst_mac:str|None=None,src_port:int|None=None,src_ip:str|None=None):
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.flags = flags
        self.src_ip = src_ip
        self.src_port = src_port
        
        protocol = protocol.lower()
        
        if protocol not in ("tcp","udp","icmp",None): # Raises error for incorrect protocols
            raise ValueError("Protocol must be either 'tcp', 'udp', or 'icmp'")
        self.protocol = protocol
            
        if isinstance(dst_port,int) and 1 <= dst_port <= 65_535: # TCP and UDP only have 65,535 ports, anything more than this is an error.
            self.dst_port = dst_port
        else:
            raise ValueError("Invalid port")
        
        if src_port is not None:
            if isinstance(src_port,int) and 1 <= src_port <= 65535:
                self.src_port = src_port
            else:
                raise ValueError("Invalid port")
            
    def create_packet(self):
        ip = IP(dst=self.dst_ip) # Sets destination IPv4 for IP layer
        
        if self.src_ip:
            ip.src = self.src_ip
        
        if self.protocol == "tcp":
            tcp = TCP(dport=self.dst_port)
            if self.src_port:
                tcp.sport = self.src_port
            if self.flags:
                tcp.flags = self.flags
            layer4 = tcp
        
        elif self.protocol == "udp":
            if self.flags:
                raise ValueError("UDP does not support flags")
            udp = UDP(dport=self.dst_port)
            if self.src_port:
                udp.sport = self.src_port
            layer4 = udp
        
        elif self.protocol == "icmp":
            if self.flags:
                raise ValueError("ICMP does not support flags")
            elif self.src_port or self.dst_port:
                raise ValueError("ICMP does not support ports")
            layer4 = ICMP()
            
        else: # Currently this program supports TCP, UDP, and ICMP
            raise ValueError("Unsupported protocol")
        
        pkt = ip / layer4
        
        if self.dst_mac: # If packet contains destination MAC address by user, the packet is automatically created at layer 2
            pkt = Ether(dst=self.dst_mac) / pkt
            
        return pkt
    
    def s_packet(self): # Sends one packet
        pkt = self.create_packet()
        
        if self.dst_mac is None: # Send is a layer 3 function while sendp is a layer 2 function, so if MAC is provided, it uses sendp
            send(pkt,verbose=1)
        else:
            sendp(pkt,verbose=1)
            
    def sr_packet(self): # Sends and receives one packet (same as above, except for srp1 and sr1)
        pkt = self.create_packet()
        
        if self.dst_mac:
            response = srp1(pkt,timeout=1,verbose=1)
        else:
            response = sr1(pkt,timeout=1,verbose=1)
            
        if response: # If packet received a response, this will print it
            print(f"Received: {response.summary()}")
        else:
            print("No response")
            
        return response
    
def main():
    p1 = Packet("129.21.108.139","ICMP",100,None,None,None,"129.21.108.254")
    p1.s_packet()
    
if __name__ == "__main__":
    main()
        
        
            
        
