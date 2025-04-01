import tkinter as tk
import threading
import time
from scapy.all import sniff, sendp, Ether, ARP, IP, TCP, UDP, ICMP

# Select interface
PORT1 = "en8"
PORT2 = "en9"

stats = {
    "port1": {
        "in":    {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
        "out":   {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
    },
    "port2": {
        "in":    {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
        "out":   {"Ethernet": 0, "ARP": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0},
    }
}

stats_lock = threading.Lock()  # Allows only one thread access

# Duplicate table to track packet hashes
duplicate_table = set()
duplicate_table_lock = threading.Lock()

# MAC table for forwarding: maps MAC addresses to interface names.
mac_table = {}
mac_table_lock = threading.Lock()

def update_protocol_counters(packet, port_name, direction):
    # Ethernet II
    if packet.haslayer(Ether):
        stats[port_name][direction]["Ethernet"] += 1

    # ARP
    if packet.haslayer(ARP):
        stats[port_name][direction]["ARP"] += 1

    # IP + ...
    if packet.haslayer(IP):
        stats[port_name][direction]["IP"] += 1

        # ICMP
        if packet.haslayer(ICMP):
            stats[port_name][direction]["ICMP"] += 1

        # TCP 
        elif packet.haslayer(TCP):
            stats[port_name][direction]["TCP"] += 1
            tcp_layer = packet[TCP]
            # Check port 80 for HTTP
            if tcp_layer.sport == 80 or tcp_layer.dport == 80:
                stats[port_name][direction]["HTTP"] += 1

        # UDP
        elif packet.haslayer(UDP):
            stats[port_name][direction]["UDP"] += 1

def process_packet(packet, in_port):
    if not packet.haslayer(Ether):
        return

    # Compute a hash for the packet's raw bytes.
    try:
        packet_bytes = bytes(packet)
        packet_hash = hash(packet_bytes)
    except Exception as e:
        print("Error computing packet hash:", e)
        return

    # Check if the packet is a duplicate.
    with duplicate_table_lock:
        if packet_hash in duplicate_table:
            # Duplicate detected, drop the packet.
            return
        else:
            duplicate_table.add(packet_hash)

    # Learn the source MAC address.
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst
    with mac_table_lock:
        mac_table[src_mac] = in_port

    # Update statistics for incoming packet.
    port_label_in = "port1" if in_port == PORT1 else "port2"
    with stats_lock:
        update_protocol_counters(packet, port_label_in, "in")

    # Determine output port(s) based on MAC table lookup.
    out_ports = []
    # Check for broadcast destination.
    if dst_mac.lower() == "ff:ff:ff:ff:ff:ff":
        out_ports = [port for port in [PORT1, PORT2] if port != in_port]
    else:
        with mac_table_lock:
            if dst_mac in mac_table:
                learned_port = mac_table[dst_mac]
                # If the destination is learned on a different port, forward it.
                if learned_port != in_port:
                    out_ports = [learned_port]
                # If the destination is on the same port, do not forward.
                else:
                    out_ports = []
            else:
                # Unknown destination: flood the packet to all ports except the ingress.
                out_ports = [port for port in [PORT1, PORT2] if port != in_port]

    # Forward the packet on each determined output port.
    for port in out_ports:
        sendp(packet, iface=port, verbose=False)
        port_label_out = "port1" if port == PORT1 else "port2"
        with stats_lock:
            update_protocol_counters(packet, port_label_out, "out")

def cleanup_duplicate_table():
    while True:
        time.sleep(30)  # timer for clear()
        with duplicate_table_lock:
            duplicate_table.clear()

# Enable promiscuous mode on the interface.
def sniff_port(port):
    sniff(iface=port, prn=lambda pkt: process_packet(pkt, port), store=False, promisc=True)

class SwitchGUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack(padx=10, pady=10)
        self.create_widgets()
        self.update_stats_display()
        self.update_mac_table_display()

    def create_widgets(self):
        # Create two frames side by side for stats and MAC table.
        self.stats_frame = tk.Frame(self)
        self.stats_frame.grid(row=0, column=0, padx=10, pady=10)
        
        self.mac_table_frame = tk.Frame(self)
        self.mac_table_frame.grid(row=0, column=1, padx=10, pady=10)
        
        # Statistics widget.
        self.stats_text = tk.Text(self.stats_frame, width=60, height=16)
        self.stats_text.pack()
        self.reset_button = tk.Button(self.stats_frame, text="Reset Statistics", command=self.reset_stats)
        self.reset_button.pack(pady=5)
        
        # MAC Table widget.
        self.mac_table_text = tk.Text(self.mac_table_frame, width=40, height=16)
        self.mac_table_text.pack()
        self.clear_mac_button = tk.Button(self.mac_table_frame, text="Clear MAC Table", command=self.clear_mac_table)
        self.clear_mac_button.pack(pady=5)

    def update_stats_display(self):
        current_scroll = self.stats_text.yview()
        display_text = ""
        with stats_lock:
            # For convenience:
            p1_in = stats["port1"]["in"]
            p1_out = stats["port1"]["out"]
            p2_in = stats["port2"]["in"]
            p2_out = stats["port2"]["out"]

            display_text = (
                "======= PORT 1 IN =======\n"
                f"Ethernet: {p1_in['Ethernet']}   ARP: {p1_in['ARP']}   IP: {p1_in['IP']}   \n"
                f"TCP: {p1_in['TCP']}        UDP: {p1_in['UDP']}   ICMP: {p1_in['ICMP']} \n"
                f"HTTP: {p1_in['HTTP']}\n\n"

                "======= PORT 1 OUT =======\n"
                f"Ethernet: {p1_out['Ethernet']}   ARP: {p1_out['ARP']}   IP: {p1_out['IP']}   \n"
                f"TCP: {p1_out['TCP']}        UDP: {p1_out['UDP']}   ICMP: {p1_out['ICMP']} \n"
                f"HTTP: {p1_out['HTTP']}\n\n"

                "======= PORT 2 IN =======\n"
                f"Ethernet: {p2_in['Ethernet']}   ARP: {p2_in['ARP']}   IP: {p2_in['IP']}   \n"
                f"TCP: {p2_in['TCP']}        UDP: {p2_in['UDP']}   ICMP: {p2_in['ICMP']} \n"
                f"HTTP: {p2_in['HTTP']}\n\n"

                "======= PORT 2 OUT =======\n"
                f"Ethernet: {p2_out['Ethernet']}   ARP: {p2_out['ARP']}   IP: {p2_out['IP']}   \n"
                f"TCP: {p2_out['TCP']}        UDP: {p2_out['UDP']}   ICMP: {p2_out['ICMP']} \n"
                f"HTTP: {p2_out['HTTP']}\n"
            )

        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert(tk.END, display_text)
        self.stats_text.yview_moveto(current_scroll[0])
        self.after(500, self.update_stats_display)  # Refresh every 500 ms

    def update_mac_table_display(self):
        mac_display = "Learned MAC Addresses:\n\n"
        with mac_table_lock:
            for mac, port in mac_table.items():
                mac_display += f"{mac} : {port}\n"
        self.mac_table_text.delete("1.0", tk.END)
        self.mac_table_text.insert(tk.END, mac_display)
        self.after(500, self.update_mac_table_display)

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

def main():
    # Start sniffing on both ports.
    t1 = threading.Thread(target=sniff_port, args=(PORT1,), daemon=True)
    t2 = threading.Thread(target=sniff_port, args=(PORT2,), daemon=True)
    t1.start()
    t2.start()

    # Start the duplicate table cleanup thread.
    cleanup_thread = threading.Thread(target=cleanup_duplicate_table, daemon=True)
    cleanup_thread.start()

    root = tk.Tk()
    root.title("Switch Statistics and MAC Table")
    app = SwitchGUI(master=root)
    root.mainloop()

if __name__ == "__main__":
    main()