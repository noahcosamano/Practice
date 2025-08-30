from scapy.all import Ether, IP, sendp, TCP, sr, sr1

def scan_ports(destination_ip,interface,start_port,end_port):
    ports_to_scan = range(start_port,end_port+1)
    
    for port in ports_to_scan:
        packet = IP(dst=destination_ip) / TCP(dport=port,flags="S")
        
        try:
            response = sr1(packet,timeout=1,verbose=0)
            #sendp(packet,interface)
        except Exception as e:
            print(f"Error scanning port {port}")
            
        if response is None:
            print(f"Port {port} is CLOSED")
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
    
            if tcp_layer.flags == 0x14:
                print(f"Port {port} is CLOSED")
            elif tcp_layer.flags == 0x12:
                reset_packet = IP(dst=destination_ip) / TCP(dport=port, flags="R")
                sr1(reset_packet, timeout=1, verbose=0)
                print(f"Port {port} is OPEN")

def main():
    scan_ports("192.168.1.183","Wi-Fi",130,140)

if __name__ == "__main__":
    main()