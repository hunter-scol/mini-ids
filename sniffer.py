from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time

knocks = {}
posAttackers = set()
attackers = set()
POS_THRESHOLD = 10
ATCK_THRESHOLD = 50
WINDOW = 5




def handle_packet(packet):
    if not packet.haslayer(TCP):
        return

    source = packet[IP].src
    destination = packet[IP].dst
    port = packet[TCP].dport
    if source not in knocks:
        knocks[source] = {}

    knocks[source][port] = time.time()

    now = time.time()
    recent = {}
    for port_num , knock_time in knocks[source].items():
        if now - knock_time <= WINDOW:
            recent[port_num] = knock_time
    knocks[source] = recent


    if len(knocks[source]) == POS_THRESHOLD and source not in posAttackers:
        posAttackers.add(source)
        print(f"possible attack: from, source: {source} to {destination}. {len(knocks[source])} probes")

    if len(knocks[source]) == ATCK_THRESHOLD and source in posAttackers and source not in attackers:
        attackers.add(source)
        print(f"attack: possible attacker {source} elevated to attacker due to excessive probes. count: {len(knocks[source])}")





sniff(iface="lo", prn=handle_packet, store=False, filter="tcp[tcpflags] == tcp-syn")