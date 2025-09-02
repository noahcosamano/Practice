from scapy.all import TCP,sr1,sr,srp1,srp,send,sendp,IP,UDP,Ether

class Packet:
    __slots__ = ["dst_ip","dst_mac","protocol","port","flags","src_port","src_ip"]
    
    def __init__(self,dst_ip:str,protocol:str,dst_port:int,flags:str|list|None=None,
                 dst_mac:str|None=None,src_port:int|None=None,src_ip:str|None=None):
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.flags = flags
        self.src_ip = src_ip
        self.src_port = src_port
        
        protocol = protocol.lower()
        
        if protocol not in ("tcp","udp","icmp",None):
            raise ValueError("Protocol must be either 'tcp', 'udp', or 'icmp'")
        self.protocol = protocol
            
        if isinstance(dst_port,int) and 1 <= dst_port <= 65535:
            self.port = dst_port
        else:
            raise ValueError("Invalid port")
        
        if src_port is not None:
            if isinstance(src_port,int) and 1 <= src_port <= 65535:
                self.src_port = src_port
            else:
                raise ValueError("Invalid port")
            
    def create_packet(self):
        ip = IP(dst=self.dst_ip)
        
        if self.src_ip:
            ip.src = self.src_ip
        
        if self.protocol == "tcp":
            tcp = TCP(dport=self.port)
            if self.src_port:
                tcp.sport = self.src_port
            if self.flags:
                tcp.flags = self.flags
            layer4 = tcp
        
        elif self.protocol == "udp":
            if self.flags:
                raise ValueError("UDP does not support flags")
            udp = UDP(dport=self.port)
            if self.src_port:
                udp.sport = self.src_port
            layer4 = udp
            
        else:
            raise ValueError("Unsupported protocol")
        
        pkt = ip / layer4
        
        if self.dst_mac:
            pkt = Ether(dst=self.dst_mac) / pkt
            
        return pkt
    
    def s_packet(self):
        pkt = self.create_packet()
        
        if self.dst_mac is None:
            send(pkt,verbose=1)
        else:
            sendp(pkt,verbose=1)
            
    def sr_packet(self):
        pkt = self.create_packet()
        
        if self.dst_mac:
            response = srp1(pkt,timeout=1,verbose=1)
        else:
            response = sr1(pkt,timeout=1,verbose=1)
            
        if response:
            print(f"Received: {response.summary()}")
        else:
            print("No response")
            
        return response
    
def main():
    p5 = Packet("129.21.72.179","tcp",22,"S")
    p5.sr_packet()
    
if __name__ == "__main__":
    main()
        
        
            
        
