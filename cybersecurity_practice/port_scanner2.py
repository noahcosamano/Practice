from scapy.all import IP, TCP, sr1, UDP, ICMP

def scan_tcp_ports(target_ip, start_port, end_port):
    ports_to_scan = range(start_port, end_port + 1)
    
    print(f"Running TCP scan on ports {start_port}-{end_port}... Estimated wait is {int((end_port - start_port) / 20)} seconds")
    
    open_ports = []
    
    for port in ports_to_scan:
        pkt = IP(dst = target_ip) / TCP(dport = port, flags = "S")
        response = sr1(pkt, timeout = 1, verbose = 0)
        
        if response is None:
            continue
        
        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            
            if tcp_layer.flags == 0x14:
                continue
            elif tcp_layer.flags == 0x12:
                open_ports.append(port)
                
        else:
            print(f"Error scanning port {port}")
    
    if len(open_ports) == 0:
        print("No open ports found")
    else:
        print(f"Open ports: {open_ports}")
        
def scan_udp_ports(target_ip, start_port, end_port):
    ports_to_scan = range(start_port, end_port + 1)
    
    print(f"Running UDP scan on ports {start_port}-{end_port}... Estimated wait is {int((end_port - start_port) / 20)} seconds")
    
    open_ports = []
    open_filtered_ports = []
    
    for port in ports_to_scan:
        pkt = IP(dst = target_ip) / UDP(dport = port)
        response = sr1(pkt, timeout = 1, verbose = 0)
        
        if response is None:
            open_filtered_ports.append(port)
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            
            if icmp_type == 3 and icmp_code == 3:
                continue
            else:
                continue
                
        else:
            open_ports.append(port)
            
    print(f"Open ports: {open_ports}\nOpen|Filtered ports: {open_filtered_ports}")
            
def main():
    #scan_tcp_ports("192.168.86.56",1,1000)
    scan_udp_ports("192.168.86.56",1,1000)
    
if __name__ == "__main__":
    main()