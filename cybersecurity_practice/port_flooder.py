from scapy.all import TCP, sr1, sr, srp1, srp, send, sendp, IP, UDP, Ether

class Packet:
    __slots__ = ["dst_ip", "dst_mac", "protocol", "port", "flags"]
    
    def __init__(self, dst_ip, protocol, port, flags = None, dst_mac = None):
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac
        self.flags = flags
        
        if protocol.lower() == "tcp":
            self.protocol = "tcp"
        elif protocol.lower() == "udp":
            self.protocol = "udp"
            
        if isinstance(port, int) and 1 <= port <= 65535:
            self.port = port
        else:
            raise ValueError("Invalid port")
            
    def create_packet(self):
        ip = IP(dst = self.dst_ip)
        
        if self.protocol == "tcp":
            tcp = TCP(dport = self.port)
            if self.flags:
                tcp.flags = self.flags
            layer4 = tcp
        
        elif self.protocol == "udp":
            if self.flags:
                raise ValueError("UDP does not support flags")
            layer4 = UDP(dport = self.port)
            
        else:
            raise ValueError("Unsupported protocol")
        
        pkt = ip / layer4
        
        if self.dst_mac:
            pkt = Ether(dst = self.dst_mac) / pkt
            
        return pkt
    
    def s_packet(self):
        pkt = self.create_packet()
        
        if self.dst_mac is None:
            send(pkt, verbose = 1)
        else:
            sendp(pkt, verbose = 1)
            
    def sr_packet(self):
        pkt = self.create_packet()
        
        if self.dst_mac:
            response = srp1(pkt, timeout = 1, verbose = 1)
        else:
            response = sr1(pkt, timeout = 1, verbose = 1)
            
        if response:
            print(f"Recieved: {response.summary()}")
        else:
            print("No response")
            
        return response
    
def main():
    p1 = Packet("129.21.72.179","TCP",80,"S")
    p1.s_packet()
    
if __name__ == "__main__":
    main()
        
        
            
        
