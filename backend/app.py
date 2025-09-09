from flask import Flask, jsonify, render_template_string
import threading, time
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from collections import defaultdict, Counter

app = Flask(__name__)

events = []   # simple in-memory log

stats = {
    'total_packets': 0,
    'packets_sent': 0,
    'packets_received': 0,
    'unique_IPs': set(),
    'bytes_sent': 0,
    'bytes_received': 0,
    'protocol_count': defaultdict(int),
    'top_sources': Counter(),
    'top_destinations': Counter(),
    'start_time': time.time()
}

def get_protocol(pkt):
    '''Extract protocol name'''
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if sport == 80 or dport == 80:
            return 'HTTP'
        elif sport == 443 or dport == 443:
            return 'HTTPS'
        elif sport == 53 or dport == 53:
            return 'DNS'
        elif sport == 21 or dport == 21:
            return 'FTP'
        elif sport == 22 or dport == 22:
            return 'SSH'
        elif sport == 25 or dport == 25:
            return 'SMTP'
        elif sport == 23 or dport == 23:
            return 'TELNET'
        else:
            return 'TCP'
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if sport == 53 or dport == 53:
            return 'DNS'
        elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
            return 'DHCP'
        elif sport == 123 or dport == 123:
            return 'NTP'
        else:
            return 'UDP'
    elif pkt.haslayer(ICMP):
        return 'ICMP'
    elif pkt.haslayer(DNS):
        return 'DNS'
    else:
        return 'Other'

def packet_handler(pkt):
    try:
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            proto = pkt.proto
            ts = time.strftime("%H:%M:%S", time.localtime())
            events.append({"time": ts, "src": src, "dst": dst, "proto": proto})
            # keep only last 200
            if len(events) > 200:
                events.pop(0)
    except Exception:
        pass

def start_sniffer():
    sniff(prn=packet_handler, store=False)



@app.route("/events")
def get_events():
    return jsonify(list(reversed(events[-200:])))

if __name__ == "__main__":
    # run sniffer in background thread
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8000)