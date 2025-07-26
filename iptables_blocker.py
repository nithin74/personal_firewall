import os
import json

# Load rules
def load_rules():
    with open("rules.json", "r") as file:
        return json.load(file)

rules = load_rules()

# Apply iptables blocking rules
def apply_iptables_rules():
    print("[*] Applying iptables rules...")
    
    # Block IPs
    for ip in rules["block"]["ip"]:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"❌ Blocked IP: {ip}")

    # Block Ports
    for port in rules["block"]["port"]:
        os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
        os.system(f"sudo iptables -A INPUT -p udp --dport {port} -j DROP")
        print(f"❌ Blocked Port: {port}")

    print("[+] iptables rules applied.")

# Flush all iptables rules (for cleanup/reset)
def reset_iptables():
    print("[!] Resetting iptables...")
    os.system("sudo iptables -F")
    print("[+] iptables rules cleared.")

# === MAIN ===
if __name__ == "__main__":
    print("1. Apply iptables rules")
    print("2. Reset (Flush) iptables rules")
    choice = input("Enter choice (1 or 2): ")

    if choice == "1":
        apply_iptables_rules()
    elif choice == "2":
        reset_iptables()
    else:
        print("Invalid choice.")
