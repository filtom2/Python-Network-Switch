import tkinter as tk
import threading
import time
from scapy.all import sniff, sendp, Ether, ARP, IP, TCP, UDP, ICMP

# Select interface
PORT1 = "en8"
PORT2 = "en9"

# Global statistics
stats = {
    "port1": {
        "in": {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
        "out": {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
    },
    "port2": {
        "in": {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
        "out": {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
    }
}
stats_lock = threading.Lock()

# Duplicate table to track packet hashes.
duplicate_table = set()
duplicate_table_lock = threading.Lock()

mac_table = {}
mac_table_lock = threading.Lock()

# Global list of ACL rules.
acl_rules = []
acl_rules_lock = threading.Lock()

# Stores last seen time and status for the interfaces
interface_status = {
    PORT1: {"last_seen": time.time(), "status": "up"},
    PORT2: {"last_seen": time.time(), "status": "up"}
    }
interface_status_lock = threading.Lock()
INTERFACE_TIMEOUT = 10  # seconds

def update_protocol_counters(packet, port_name, direction):
    if packet.haslayer(Ether):
        stats[port_name][direction]["Ethernet"] += 1
    if packet.haslayer(ARP):
        stats[port_name][direction]["ARP"] += 1
    if packet.haslayer(IP):
        stats[port_name][direction]["IP"] += 1
        if packet.haslayer(ICMP):
            stats[port_name][direction]["ICMP"] += 1
        elif packet.haslayer(TCP):
            stats[port_name][direction]["TCP"] += 1
            tcp_layer = packet[TCP]
            if tcp_layer.sport == 80 or tcp_layer.dport == 80:
                stats[port_name][direction]["HTTP"] += 1
        elif packet.haslayer(UDP):
            stats[port_name][direction]["UDP"] += 1

def acl_check(packet, direction, port_label):
    with acl_rules_lock:
        for rule in acl_rules:
            rule_direction = rule.get("direction", "all")
            if rule_direction != "all" and rule_direction != direction:
                continue
            rule_port = rule.get("port", "all")
            if rule_port != "all" and rule_port != port_label:
                continue
            if "src_mac" in rule:
                if not packet.haslayer(Ether) or packet[Ether].src.lower() != rule["src_mac"].lower():
                    continue
            if "dst_mac" in rule:
                if not packet.haslayer(Ether) or packet[Ether].dst.lower() != rule["dst_mac"].lower():
                    continue
            if "src_ip" in rule:
                if not packet.haslayer(IP) or packet[IP].src != rule["src_ip"]:
                    continue
            if "dst_ip" in rule:
                if not packet.haslayer(IP) or packet[IP].dst != rule["dst_ip"]:
                    continue
            if "src_port" in rule:
                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                elif packet.haslayer(UDP):
                    sport = packet[UDP].sport
                else:
                    continue
                if int(sport) != int(rule["src_port"]):
                    continue
            if "dst_port" in rule:
                if packet.haslayer(TCP):
                    dport = packet[TCP].dport
                elif packet.haslayer(UDP):
                    dport = packet[UDP].dport
                else:
                    continue
                if int(dport) != int(rule["dst_port"]):
                    continue
            if "icmp_type" in rule:
                if not packet.haslayer(ICMP):
                    continue
                if int(packet[ICMP].type) != int(rule["icmp_type"]):
                    continue
            if rule.get("action", "permit") == "deny":
                return False
            elif rule.get("action", "permit") == "permit":
                return True
    return True

def process_packet(packet, in_port):
    if not packet.haslayer(Ether):
        return

    try:
        packet_bytes = bytes(packet)
        packet_hash = hash(packet_bytes)
    except Exception as e:
        print("Error computing packet hash:", e)
        return

    with duplicate_table_lock:
        if packet_hash in duplicate_table:
            return
        else:
            duplicate_table.add(packet_hash)

    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst
    with mac_table_lock:
        mac_table[src_mac] = {"port": in_port, "timestamp": time.time()}

    # --- Update interface status for the incoming port ---
    with interface_status_lock:
        interface_status[in_port]["last_seen"] = time.time()
        interface_status[in_port]["status"] = "up"

    port_label_in = "port1" if in_port == PORT1 else "port2"
    if not acl_check(packet, "in", port_label_in):
        return

    with stats_lock:
        update_protocol_counters(packet, port_label_in, "in")

    out_ports = []
    if dst_mac.lower() == "ff:ff:ff:ff:ff:ff":
        out_ports = [port for port in [PORT1, PORT2] if port != in_port]
    else:
        with mac_table_lock:
            if dst_mac in mac_table:
                learned_port = mac_table[dst_mac]["port"]
                if learned_port != in_port:
                    out_ports = [learned_port]
                else:
                    out_ports = []
            else:
                out_ports = [port for port in [PORT1, PORT2] if port != in_port]

    for port in out_ports:
        port_label_out = "port1" if port == PORT1 else "port2"
        # Before sending, check if the out_port is marked as "up"
        with interface_status_lock:
            if interface_status.get(port, {}).get("status") != "up":
                # Skip sending on an interface that's considered down.
                continue
        if not acl_check(packet, "out", port_label_out):
            continue
        sendp(packet, iface=port, verbose=False)
        with stats_lock:
            update_protocol_counters(packet, port_label_out, "out")

def cleanup_duplicate_table():
    while True:
        time.sleep(30)
        with duplicate_table_lock:
            duplicate_table.clear()

def mac_table_aging():
    while True:
        time.sleep(1)
        now = time.time()
        with mac_table_lock:
            to_delete = [mac for mac, info in mac_table.items() if now - info["timestamp"] > 30]
            for mac in to_delete:
                del mac_table[mac]

def monitor_interfaces():
    while True:
        time.sleep(1)
        now = time.time()
        with interface_status_lock:
            for iface, info in interface_status.items():
                if now - info["last_seen"] > INTERFACE_TIMEOUT:
                    if info["status"] != "down":
                        info["status"] = "down"
                        print(f"Interface {iface} marked as down due to inactivity.")
                        
def sniff_port(port):
    sniff(iface=port, prn=lambda pkt: process_packet(pkt, port), store=False, promisc=True)

# GUI class
class SwitchGUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack(padx=10, pady=10)
        self.create_widgets()
        self.update_stats_display()
        self.update_mac_table_display()
        self.update_acl_display()

    def create_widgets(self):
        self.stats_frame = tk.Frame(self)
        self.stats_frame.grid(row=0, column=0, padx=10, pady=10)
        
        self.mac_table_frame = tk.Frame(self)
        self.mac_table_frame.grid(row=0, column=1, padx=10, pady=10)
        
        self.acl_frame = tk.Frame(self)
        self.acl_frame.grid(row=0, column=2, padx=10, pady=10)
        
        self.stats_text = tk.Text(self.stats_frame, width=60, height=16)
        self.stats_text.pack()
        self.reset_button = tk.Button(self.stats_frame, text="Reset Statistics", command=self.reset_stats)
        self.reset_button.pack(pady=5)
        
        self.mac_table_text = tk.Text(self.mac_table_frame, width=40, height=16)
        self.mac_table_text.pack()
        self.clear_mac_button = tk.Button(self.mac_table_frame, text="Clear MAC Table", command=self.clear_mac_table)
        self.clear_mac_button.pack(pady=5)
        
        self.acl_listbox = tk.Listbox(self.acl_frame, width=60, height=16)
        self.acl_listbox.pack()
        self.acl_add_button = tk.Button(self.acl_frame, text="Add ACL Rule", command=self.add_acl_rule)
        self.acl_add_button.pack(pady=5)
        self.acl_delete_button = tk.Button(self.acl_frame, text="Delete Selected ACL Rule", command=self.delete_acl_rule)
        self.acl_delete_button.pack(pady=5)

    def update_stats_display(self):
        current_scroll = self.stats_text.yview()
        display_text = ""
        with stats_lock:
            p1_in = stats["port1"]["in"]
            p1_out = stats["port1"]["out"]
            p2_in = stats["port2"]["in"]
            p2_out = stats["port2"]["out"]
            display_text = (
                "======= PORT 1 IN =======\n"
                f"Ethernet: {p1_in['Ethernet']}   ARP: {p1_in['ARP']}   IP: {p1_in['IP']}\n"
                f"TCP: {p1_in['TCP']}   UDP: {p1_in['UDP']}   ICMP: {p1_in['ICMP']}   HTTP: {p1_in['HTTP']}\n\n"
                "======= PORT 1 OUT =======\n"
                f"Ethernet: {p1_out['Ethernet']}   ARP: {p1_out['ARP']}   IP: {p1_out['IP']}\n"
                f"TCP: {p1_out['TCP']}   UDP: {p1_out['UDP']}   ICMP: {p1_out['ICMP']}   HTTP: {p1_out['HTTP']}\n\n"
                "======= PORT 2 IN =======\n"
                f"Ethernet: {p2_in['Ethernet']}   ARP: {p2_in['ARP']}   IP: {p2_in['IP']}\n"
                f"TCP: {p2_in['TCP']}   UDP: {p2_in['UDP']}   ICMP: {p2_in['ICMP']}   HTTP: {p2_in['HTTP']}\n\n"
                "======= PORT 2 OUT =======\n"
                f"Ethernet: {p2_out['Ethernet']}   ARP: {p2_out['ARP']}   IP: {p2_out['IP']}\n"
                f"TCP: {p2_out['TCP']}   UDP: {p2_out['UDP']}   ICMP: {p2_out['ICMP']}   HTTP: {p2_out['HTTP']}\n"
            )
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert(tk.END, display_text)
        self.stats_text.yview_moveto(current_scroll[0])
        self.after(500, self.update_stats_display)

    def update_mac_table_display(self):
        mac_display = "Learned MAC Addresses:\n\n"
        with mac_table_lock:
            for mac, info in mac_table.items():
                mac_display += f"{mac} : {info['port']} (last seen: {int(time.time()-info['timestamp'])}s ago)\n"
        self.mac_table_text.delete("1.0", tk.END)
        self.mac_table_text.insert(tk.END, mac_display)
        self.after(500, self.update_mac_table_display)

    def update_acl_display(self):
        self.acl_listbox.delete(0, tk.END)
        with acl_rules_lock:
            for idx, rule in enumerate(acl_rules):
                rule_text = f"{idx}: {rule}"
                self.acl_listbox.insert(tk.END, rule_text)

    def reset_stats(self):
        with stats_lock:
            for direction in ("in", "out"):
                for protocol in stats["port1"][direction]:
                    stats["port1"][direction][protocol] = 0
                for protocol in stats["port2"][direction]:
                    stats["port2"][direction][protocol] = 0

    def clear_mac_table(self):
        with mac_table_lock:
            mac_table.clear()

    def add_acl_rule(self):
        def submit_rule():
            rule = {}
            rule["action"] = action_var.get()
            rule["direction"] = direction_var.get()
            rule["port"] = port_var.get()
            src_mac_val = src_mac_entry.get().strip()
            if src_mac_val:
                rule["src_mac"] = src_mac_val
            dst_mac_val = dst_mac_entry.get().strip()
            if dst_mac_val:
                rule["dst_mac"] = dst_mac_val
            src_ip_val = src_ip_entry.get().strip()
            if src_ip_val:
                rule["src_ip"] = src_ip_val
            dst_ip_val = dst_ip_entry.get().strip()
            if dst_ip_val:
                rule["dst_ip"] = dst_ip_val
            src_port_val = src_port_entry.get().strip()
            if src_port_val:
                rule["src_port"] = src_port_val
            dst_port_val = dst_port_entry.get().strip()
            if dst_port_val:
                rule["dst_port"] = dst_port_val
            icmp_type_val = icmp_type_entry.get().strip()
            if icmp_type_val:
                rule["icmp_type"] = icmp_type_val

            with acl_rules_lock:
                acl_rules.append(rule)
            self.update_acl_display()
            add_window.destroy()

        add_window = tk.Toplevel(self)
        add_window.title("Add ACL Rule")
        tk.Label(add_window, text="Action:").grid(row=0, column=0)
        action_var = tk.StringVar(value="permit")
        action_menu = tk.OptionMenu(add_window, action_var, "permit", "deny")
        action_menu.grid(row=0, column=1)
        tk.Label(add_window, text="Direction:").grid(row=1, column=0)
        direction_var = tk.StringVar(value="in")
        direction_menu = tk.OptionMenu(add_window, direction_var, "in", "out")
        direction_menu.grid(row=1, column=1)
        tk.Label(add_window, text="Port:").grid(row=2, column=0)
        port_var = tk.StringVar(value="all")
        port_menu = tk.OptionMenu(add_window, port_var, "all", "port1", "port2")
        port_menu.grid(row=2, column=1)
        tk.Label(add_window, text="Source MAC (optional):").grid(row=3, column=0)
        src_mac_entry = tk.Entry(add_window)
        src_mac_entry.grid(row=3, column=1)
        tk.Label(add_window, text="Destination MAC (optional):").grid(row=4, column=0)
        dst_mac_entry = tk.Entry(add_window)
        dst_mac_entry.grid(row=4, column=1)
        tk.Label(add_window, text="Source IP (optional):").grid(row=5, column=0)
        src_ip_entry = tk.Entry(add_window)
        src_ip_entry.grid(row=5, column=1)
        tk.Label(add_window, text="Destination IP (optional):").grid(row=6, column=0)
        dst_ip_entry = tk.Entry(add_window)
        dst_ip_entry.grid(row=6, column=1)
        tk.Label(add_window, text="Source Port (optional):").grid(row=7, column=0)
        src_port_entry = tk.Entry(add_window)
        src_port_entry.grid(row=7, column=1)
        tk.Label(add_window, text="Destination Port (optional):").grid(row=8, column=0)
        dst_port_entry = tk.Entry(add_window)
        dst_port_entry.grid(row=8, column=1)
        tk.Label(add_window, text="ICMP Type (optional):").grid(row=9, column=0)
        icmp_type_entry = tk.Entry(add_window)
        icmp_type_entry.grid(row=9, column=1)
        submit_button = tk.Button(add_window, text="Add Rule", command=submit_rule)
        submit_button.grid(row=10, column=0, columnspan=2)

    def delete_acl_rule(self):
        selection = self.acl_listbox.curselection()
        if selection:
            idx = int(selection[0])
            with acl_rules_lock:
                if idx < len(acl_rules):
                    del acl_rules[idx]
            self.update_acl_display()

def main():
    t1 = threading.Thread(target=sniff_port, args=(PORT1,), daemon=True)
    t2 = threading.Thread(target=sniff_port, args=(PORT2,), daemon=True)
    t1.start()
    t2.start()

    cleanup_thread = threading.Thread(target=cleanup_duplicate_table, daemon=True)
    cleanup_thread.start()

    aging_thread = threading.Thread(target=mac_table_aging, daemon=True)
    aging_thread.start()

    interface_monitor_thread = threading.Thread(target=monitor_interfaces, daemon=True)
    interface_monitor_thread.start()


    root = tk.Tk()
    root.title("Switch Statistics, MAC Table and ACL Rules")
    app = SwitchGUI(master=root)
    root.mainloop()

if __name__ == "__main__":
    main()