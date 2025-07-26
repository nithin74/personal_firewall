import json
import time
import threading
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

def load_rules():
    with open("rules.json", "r") as file:
        return json.load(file)

rules = load_rules()

def get_protocol_name(proto_num):
    if proto_num == 6:
        return "TCP"
    elif proto_num == 17:
        return "UDP"
    elif proto_num == 1:
        return "ICMP"
    else:
        return str(proto_num)

def is_blocked(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        proto = ip_layer.proto

        if src_ip in rules["block"]["ip"]:
            return True

        if get_protocol_name(proto) in rules["block"]["protocol"]:
            return True

        if TCP in packet:
            if packet[TCP].sport in rules["block"]["port"] or packet[TCP].dport in rules["block"]["port"]:
                return True
        elif UDP in packet:
            if packet[UDP].sport in rules["block"]["port"] or packet[UDP].dport in rules["block"]["port"]:
                return True
    return False

def log_blocked_packet(packet):
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

        log_line = f"{timestamp} BLOCKED {proto} {src_ip} -> {dst_ip} {ports}"
        log_file.write(log_line + "\n")
        log_message("❌ " + log_line)

root = tk.Tk()
root.title("Python Personal Firewall GUI")

output_box = ScrolledText(root, height=25, width=100, font=("Courier", 10))
output_box.pack(padx=10, pady=10)

status_label = tk.Label(root, text="Status: 🔴 Stopped", font=("Helvetica", 12), fg="red")
status_label.pack(pady=5)

def log_message(msg):
    output_box.insert(tk.END, msg + "\n")
    output_box.see(tk.END)

sniffing = False
sniffer_thread = None

def process_packet(packet):
    if is_blocked(packet):
        log_blocked_packet(packet)
    else:
        log_message("✅ ALLOWED: " + packet.summary())

def sniff_packets():
    sniff(prn=process_packet, store=0)

def start_firewall():
    global sniffing, sniffer_thread
    if not sniffing:
        sniffing = True
        sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffer_thread.start()
        status_label.config(text="Status: 🟢 Running", fg="green")
        log_message("[*] Firewall started.")

def stop_firewall():
    global sniffing
    sniffing = False
    status_label.config(text="Status: 🔴 Stopped", fg="red")
    log_message("[!] Firewall stopped. (Press CTRL+C to fully halt sniffing thread if needed)")

def apply_iptables_rules():
    log_message("[*] Applying iptables rules from GUI...")

    # Prevent duplicate rules by flushing first
    os.system("sudo iptables -F")

    for ip in rules["block"]["ip"]:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        log_message(f"❌ Blocked IP via iptables: {ip}")

    for port in rules["block"]["port"]:
        os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
        os.system(f"sudo iptables -A INPUT -p udp --dport {port} -j DROP")
        log_message(f"❌ Blocked Port via iptables: {port}")

    log_message("[+] iptables rules applied.")



def reset_iptables_rules():
    log_message("[!] Resetting iptables (flush)...")
    os.system("sudo iptables -F")
    log_message("[+] iptables rules cleared.")

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Firewall", command=start_firewall, width=20, bg="green", fg="white")
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="Stop Firewall", command=stop_firewall, width=20, bg="red", fg="white")
stop_button.pack(side=tk.LEFT, padx=5)

iptables_button = tk.Button(button_frame, text="Apply iptables Rules", command=apply_iptables_rules, width=20, bg="blue", fg="white")
iptables_button.pack(side=tk.LEFT, padx=5)

flush_button = tk.Button(button_frame, text="Reset iptables", command=reset_iptables_rules, width=20, bg="orange", fg="black")
flush_button.pack(side=tk.LEFT, padx=5)

root.mainloop()
