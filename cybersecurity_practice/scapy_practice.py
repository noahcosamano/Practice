from scapy.all import IP, Ether, TCP, send, sendp

packet = Ether() / IP(dst="129.21.72.179",src="129.21.108.139") / TCP(flags="S")
sendp(packet, iface="Wi-Fi")



