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
    
def get_ports(pkt):
    '''Extract source and destination ports'''
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    else:
        return None, None
    
def packet_handler(pkt):
    try:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            packet_size = len(pkt)
            proto = get_protocol(pkt)
            ts = time.strftime("%H:%M:%S", time.localtime())
            sport, dport = get_ports(pkt)

            # update stats
            stats['total_packets'] +=1
            stats['unique_IPs'].update([src, dst])
            stats['protocol_count'][proto] +=1
            stats['top_sources'][src] +=1
            stats['top_destinations'][dst] +=1

            # determine sent vs received
            if src.startswith(('192.168.', '10.', '172.')):
                stats['packets_sent'] +=1
                stats['bytes_sent'] += packet_size
            else:
                stats['packets_received'] +=1
                stats['bytes_received'] += packet_size
            
            #create event log
            event={
                'time': ts,
                'src': src,
                'dst': dst,
                'sport': sport,
                'dport': dport,
                'protocol': proto,
                'size': packet_size
            }

            events.append(event)

            # keep only last 200
            if len(events) > 200:
                events.pop(0)
 
    except Exception as e:
        pass

def start_sniffer():
    try:
        sniff(prn=packet_handler, store=False)
    except Exception as e:
        print(f"Error starting sniffer: {e}")



@app.route("/events")
def get_events():
    return jsonify(list(reversed(events[-200:])))

@app.route("/stats")
def get_stats():
    uptime = int(time.time() - stats['start_time'])
    return jsonify({
        'total_packets': stats['total_packets'],
        'packets_sent': stats['packets_sent'],
        'packets_received': stats['packets_received'],
        'unique_IPs': len(stats['unique_IPs']),
        'bytes_sent': stats['bytes_sent'],
        'bytes_received': stats['bytes_received'],
        'protocol_count': stats['protocol_count'],
        'top_sources': stats['top_sources'].most_common(10),
        'top_destinations': stats['top_destinations'].most_common(10),
        'uptime': uptime,
        'packets_per_second': stats['total_packets'] / max(uptime, 1)
    })

if __name__ == "__main__":
    # run sniffer in background thread
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8000)