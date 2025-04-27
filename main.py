import tkinter as tk
import threading
import time
import socket
from scapy.all import sniff, sendp, Ether, ARP, IP, TCP, UDP, ICMP


SYSLOG_SERVER_IP = "172.16.0.3"
SYSLOG_SOURCE_IP = "172.16.0.10"
SYSLOG_ENABLED   = False
SEVERITY = {"info": 6, "warning": 4, "critical": 2}
FACILITY = 23
MAC_TABLE_TIMEOUT = 30  # seconds to remember learned MAC addresses

def send_syslog(msg, sev="info"):
    if not SYSLOG_ENABLED:
        return
    pri = FACILITY * 8 + SEVERITY.get(sev, 6)
    ts = time.strftime("%b %d %H:%M:%S", time.localtime())
    host = socket.gethostname()
    payload = f"<{pri}>{ts} {host} {msg}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((SYSLOG_SOURCE_IP, 0))
        s.sendto(payload.encode(), (SYSLOG_SERVER_IP, 514))
        s.close()
    except Exception as e:
        print("Syslog error:", e)

def start_syslog():
    global SYSLOG_ENABLED
    if SYSLOG_ENABLED:
        return 
    SYSLOG_ENABLED = True
    send_syslog("Syslog started", "info")

def stop_syslog():
    global SYSLOG_ENABLED
    if not SYSLOG_ENABLED:
        return 
    send_syslog("Syslog stopped", "info")
    SYSLOG_ENABLED = False

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

duplicate_table = set()
duplicate_table_lock = threading.Lock()

mac_table = {}
mac_table_lock = threading.Lock()

acl_rules = []
acl_rules_lock = threading.Lock()

interface_status = {
    PORT1: {"last_seen": time.time(), "status": "up"},
    PORT2: {"last_seen": time.time(), "status": "up"}
}
interface_status_lock = threading.Lock()
INTERFACE_TIMEOUT = 10 # seconds

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
                send_syslog(f"Packet from {packet[Ether].src} to {packet[Ether].dst} denied by ACL: {rule}", "warning")
                return False
            elif rule.get("action", "permit") == "permit":
                return True
    return True

def process_packet(packet, in_port):
    if not packet.haslayer(Ether):
        return
    try:
        packet_hash = hash(bytes(packet))
    except Exception:
        return
    with duplicate_table_lock:
        if packet_hash in duplicate_table:
            return
        duplicate_table.add(packet_hash)

    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst

    # MAC learn / move / timestamp
    with mac_table_lock:
        prev_port = mac_table.get(src_mac, {}).get("port")
        moved = prev_port and prev_port != in_port
        new   = prev_port is None
        mac_table[src_mac] = {"port": in_port, "timestamp": time.time()}
    # Handle MAC movement or new learning of an address
    if moved:
        send_syslog(f"MAC {src_mac} moved from {prev_port} to {in_port}", "warning")
    elif new:
        send_syslog(f"MAC {src_mac} learned on {in_port}", "info")

    # interface status update
    with interface_status_lock:
        was_down = interface_status[in_port]["status"] == "down"
        interface_status[in_port]["last_seen"] = time.time()
        interface_status[in_port]["status"] = "up"
    if was_down:
        send_syslog(f"Interface {in_port} is up", "info")

    port_label_in = "port1" if in_port == PORT1 else "port2"
    if not acl_check(packet, "in", port_label_in):
        return

    with stats_lock:
        update_protocol_counters(packet, port_label_in, "in")

    # Determine outgoing ports from destination MAC
    out_ports = []
    if dst_mac.lower() == "ff:ff:ff:ff:ff:ff":
        out_ports = [p for p in (PORT1, PORT2) if p != in_port]
    else:
        with mac_table_lock:
            if dst_mac in mac_table:
                learned_port = mac_table[dst_mac]["port"]
                if learned_port != in_port:
                    out_ports = [learned_port]
            else:
                out_ports = [p for p in (PORT1, PORT2) if p != in_port]

    for port in out_ports:
        with interface_status_lock:
            if interface_status.get(port, {}).get("status") != "up":
                continue
        port_label_out = "port1" if port == PORT1 else "port2"
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
            for mac in [m for m,i in mac_table.items() if now - i["timestamp"] > MAC_TABLE_TIMEOUT]:
                del mac_table[mac]

def monitor_interfaces():
    while True:
        time.sleep(1)
        now = time.time()
        with interface_status_lock:
            for iface, info in interface_status.items():
                if now - info["last_seen"] > INTERFACE_TIMEOUT and info["status"] != "down":
                    info["status"] = "down"
                    print(f"Interface {iface} marked as down due to inactivity.")
                    send_syslog(f"Interface {iface} down (inactivity)", "critical")

def sniff_port(port):
    sniff(iface=port, prn=lambda p: process_packet(p, port), store=False, promisc=True)

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

        self.syslog_frame = tk.Frame(self)
        self.syslog_frame.grid(row=1, column=0, columnspan=3, pady=10)
        tk.Label(self.syslog_frame, text="Syslog source IP:").grid(row=0, column=0)
        self.src_ip_entry = tk.Entry(self.syslog_frame, width=15)
        self.src_ip_entry.insert(0, SYSLOG_SOURCE_IP)
        self.src_ip_entry.grid(row=0, column=1)
        tk.Label(self.syslog_frame, text="Server IP:").grid(row=0, column=2)
        self.dst_ip_entry = tk.Entry(self.syslog_frame, width=15)
        self.dst_ip_entry.insert(0, SYSLOG_SERVER_IP)
        self.dst_ip_entry.grid(row=0, column=3)
        tk.Label(self.syslog_frame, text="MAC Aging Timeout (s):").grid(row=1, column=0)
        self.mac_timeout_entry = tk.Entry(self.syslog_frame, width=5)
        self.mac_timeout_entry.insert(0, str(MAC_TABLE_TIMEOUT))
        self.mac_timeout_entry.grid(row=1, column=1)
        tk.Button(self.syslog_frame, text="Apply", command=self.apply_syslog_conf).grid(row=0, column=4, padx=5)
        tk.Button(self.syslog_frame, text="Start", command=start_syslog).grid(row=0, column=5, padx=3)
        tk.Button(self.syslog_frame, text="Stop", command=stop_syslog).grid(row=0, column=6, padx=3)

    def apply_syslog_conf(self):
        global SYSLOG_SOURCE_IP, SYSLOG_SERVER_IP, MAC_TABLE_TIMEOUT
        SYSLOG_SOURCE_IP = self.src_ip_entry.get().strip()
        SYSLOG_SERVER_IP = self.dst_ip_entry.get().strip()
        try:
            MAC_TABLE_TIMEOUT = int(self.mac_timeout_entry.get().strip())
        except ValueError:
            pass

    def update_stats_display(self):
        cur = self.stats_text.yview()
        with stats_lock:
            p1_in, p1_out = stats["port1"]["in"], stats["port1"]["out"]
            p2_in, p2_out = stats["port2"]["in"], stats["port2"]["out"]
            txt = (
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
        self.stats_text.insert(tk.END, txt)
        self.stats_text.yview_moveto(cur[0])
        self.after(500, self.update_stats_display)

    def update_mac_table_display(self):
        with mac_table_lock:
            lines = [f"{mac} : {info['port']} ({int(time.time()-info['timestamp'])}s ago)" for mac,info in mac_table.items()]
        self.mac_table_text.delete("1.0", tk.END)
        self.mac_table_text.insert(tk.END, "Learned MAC Addresses:\n\n"+"\n".join(lines))
        self.after(500, self.update_mac_table_display)

    def update_acl_display(self):
        self.acl_listbox.delete(0, tk.END)
        with acl_rules_lock:
            for idx, rule in enumerate(acl_rules):
                self.acl_listbox.insert(tk.END, f"{idx}: {rule}")

    def reset_stats(self):
        with stats_lock:
            for d in ("in","out"):
                for p in stats["port1"][d]:
                    stats["port1"][d][p] = 0
                    stats["port2"][d][p] = 0

    def clear_mac_table(self):
        with mac_table_lock:
            mac_table.clear()

    def add_acl_rule(self):
        def submit():
            rule = {"action": action.get(), "direction": direction.get(), "port": port.get()}
            if src_mac.get().strip(): rule["src_mac"]=src_mac.get().strip()
            if dst_mac.get().strip(): rule["dst_mac"]=dst_mac.get().strip()
            if src_ip.get().strip():  rule["src_ip"]=src_ip.get().strip()
            if dst_ip.get().strip():  rule["dst_ip"]=dst_ip.get().strip()
            if src_port.get().strip():rule["src_port"]=src_port.get().strip()
            if dst_port.get().strip():rule["dst_port"]=dst_port.get().strip()
            if icmp_type.get().strip():rule["icmp_type"]=icmp_type.get().strip()
            with acl_rules_lock:
                acl_rules.append(rule)
            send_syslog(f"ACL rule added: {rule}", "info")
            self.update_acl_display()
            w.destroy()

        w = tk.Toplevel(self)
        w.title("Add ACL Rule")
        action, direction, port = tk.StringVar(w,"permit"), tk.StringVar(w,"in"), tk.StringVar(w,"all")
        for idx,(lab,var,opts) in enumerate([("Action",action,["permit","deny"]),
                                             ("Direction",direction,["in","out"]),
                                             ("Port",port,["all","port1","port2"])]):
            tk.Label(w,text=f"{lab}:").grid(row=idx,column=0)
            tk.OptionMenu(w,var,*opts).grid(row=idx,column=1)
        labels = ["Source MAC","Destination MAC","Source IP","Destination IP","Source Port","Destination Port","ICMP Type (e.g. 8, 0, ...)"]
        src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,icmp_type=[tk.StringVar(w) for _ in range(7)]
        evars = [src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,icmp_type]
        for i, l in enumerate(labels, 3):
            tk.Label(w, text=l).grid(row=i, column=0)
            tk.Entry(w, textvariable=evars[i-3]).grid(row=i, column=1)
        tk.Button(w,text="Add Rule",command=submit).grid(row=10,column=0,columnspan=2)

    def delete_acl_rule(self):
        sel=self.acl_listbox.curselection()
        if sel:
            idx=int(sel[0])
            with acl_rules_lock:
                if idx<len(acl_rules):
                    rule=acl_rules[idx]
                    del acl_rules[idx]
            send_syslog(f"ACL rule deleted: {rule}", "warning")
            self.update_acl_display()

def main():
    threading.Thread(target=sniff_port,args=(PORT1,),daemon=True).start()
    threading.Thread(target=sniff_port,args=(PORT2,),daemon=True).start()
    threading.Thread(target=cleanup_duplicate_table,daemon=True).start()
    threading.Thread(target=mac_table_aging,daemon=True).start()
    threading.Thread(target=monitor_interfaces,daemon=True).start()

    root=tk.Tk()
    root.title("Switch Statistics, MAC Table and ACL Rules")
    SwitchGUI(master=root)
    root.mainloop()

if __name__=="__main__":
    main()