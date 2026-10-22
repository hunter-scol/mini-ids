from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time

knocks = {}
posAttackers = set()
attackers = set()
POS_THRESHOLD = 10
ATCK_THRESHOLD = 50
now = time.time()
recent = {}




def handle_packet(packet):
    if not packet.haslayer(TCP):
        return

    source = packet[IP].src
    destination = packet[IP].dst
    port = packet[TCP].dport
    if source not in knocks:
        knocks[source] = {}

    knocks[source][port] = time.time()
    if len(knocks[source]) == POS_THRESHOLD and source not in posAttackers:
        posAttackers.add(source)
        print(f"possible attack :source: {source} to {destination}. {len(knocks[source])} probes")

    if len(knocks[source]) == ATCK_THRESHOLD and source in posAttackers and source not in attackers:
        attackers.add(source)
        print(f"attack: possible attacker {source} elivated to attacker due to excessive probes. count: {len(knocks[source])}")





sniff(iface="lo", prn=handle_packet, store=False, filter="tcp[tcpflags] == tcp-syn")