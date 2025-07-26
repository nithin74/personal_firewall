import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

# Load rules from rules.json
def load_rules():
    with open("rules.json", "r") as file:
        return json.load(file)

rules = load_rules()

# Convert protocol number to name
def get_protocol_name(proto_num):
    if proto_num == 6:
        return "TCP"
    elif proto_num == 17:
        return "UDP"
    elif proto_num == 1:
        return "ICMP"
    else:
        return str(proto_num)

# Check if packet matches block rules
def is_blocked(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        proto = ip_layer.proto

        # Block by IP
        if src_ip in rules["block"]["ip"]:
            return True

        # Block by Protocol
        protocol_name = get_protocol_name(proto)
        if protocol_name in rules["block"]["protocol"]:
            return True

        # Block by Port
        if TCP in packet:
            if packet[TCP].sport in rules["block"]["port"] or packet[TCP].dport in rules["block"]["port"]:
                return True
        elif UDP in packet:
            if packet[UDP].sport in rules["block"]["port"] or packet[UDP].dport in rules["block"]["port"]:
                return True

    return False

# Log blocked packet
def log_blocked_packet(packet):
    try:
        with open("logs/blocked.log", "a") as log_file:
            timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = get_protocol_name(packet[IP].proto)
            ports = ""

            if TCP in packet:
                ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
            elif ICMP in packet:
                ports = "ICMP"

            log_line = f"{timestamp} BLOCKED {proto} {src_ip} -> {dst_ip} {ports}\n"
            log_file.write(log_line)
    except Exception as e:
        print("Logging Error:", e)

# Handle each packet
def process_packet(packet):
    if is_blocked(packet):
        print("❌ Blocked:", packet.summary())
        log_blocked_packet(packet)
    else:
        print("✅ Allowed:", packet.summary())

# Start the firewall
print("[*] Starting personal firewall... (Press Ctrl+C to stop)")
sniff(prn=process_packet, store=0)
