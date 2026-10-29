from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import time, argparse, os

parser = argparse.ArgumentParser(description='Scan a network for probes and be alerted at suspicious behavior')
parser.add_argument("--iface", default="lo", help="interface to use")
parser.add_argument("--pos-threshold", type=int, default=10, help="number of probes allowed before a source is considered a possible attacker")
parser.add_argument("--atck-threshold", type=int, default=50, help="number of probes allowed before a possible attacker is considered an attacker")
parser.add_argument("--window-knock", type=int, default=5, help="number seconds in a segment of tracked probes")
parser.add_argument("--window-pos", type=int, default=5, help="number seconds before a source can be reconsidered a possible attacker")
parser.add_argument("--window-atck", type=int, default=5, help="number seconds before a source can be reconsidered an attacker")

args = parser.parse_args()
iface = args.iface
POS_THRESHOLD = args.pos_threshold
ATCK_THRESHOLD = args.atck_threshold
WINDOW_KNOCK = args.window_knock
WINDOW_POS = args.window_pos
WINDOW_ATCK = args.window_atck
knocks = {}
recentPos = {}
recentAttackers = {}
posAttackers = set()
attackers = {}

print(f"iface setting: {iface}")
print(f"POS_THRESHOLD: {POS_THRESHOLD}")
print(f"ATCK_THRESHOLD: {ATCK_THRESHOLD}")
print(f"WINDOW: {WINDOW_KNOCK}")
print(f"WINDOW_POS: {WINDOW_POS}")
print(f"WINDOW_ATCK: {WINDOW_ATCK}")

if not os.path.exists("alerts.log") or os.path.getsize("alerts.log") == 0:
    with open("alerts.log", "a") as f:
        f.write("time,source,probes,times_escalated\n")

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
    recentKnocks = {}
    for port_num , knock_time in knocks[source].items():
        if now - knock_time <= WINDOW_KNOCK:
            recentKnocks[port_num] = knock_time
    knocks[source] = recentKnocks


    if len(knocks[source]) == POS_THRESHOLD and source not in posAttackers:
        posAttackers.add(source)
        if source not in recentPos or now - recentPos[source] > WINDOW_POS:
            print(f"possible attack: source {source} to {destination}. {len(knocks[source])} probes")
            recentPos[source] = now
    if len(knocks[source]) == ATCK_THRESHOLD and source in posAttackers:
        attackers[source] = attackers.get(source,0) + 1
        with open("alerts.log", "a") as f:
            entry = (f"{time.ctime(now)}, {source}, {len(knocks[source])}, {attackers[source]}\n")
            f.write(entry)
        if source not in recentAttackers or now - recentAttackers[source] > WINDOW_ATCK:
            print(f"attack: possible attacker {source} elevated to attacker due to excessive probes. count: {len(knocks[source])}")
            recentAttackers[source] = now
        posAttackers.discard(source)
        knocks[source] = {}



sniff(iface=iface, prn=handle_packet, store=False, filter="tcp[tcpflags] == tcp-syn")