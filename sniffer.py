from scapy.all import sniff
from scapy.layers.inet import IP, TCP

def handle_packet(packet):
    if not packet.haslayer(TCP):
        return

    source = packet[IP].src
    destination = packet[IP].dst
    port = packet[TCP].dport
    print(f"Source: {source}, Destination: {destination}, Port: {port}")



sniff(iface="lo", prn=handle_packet, store=False)