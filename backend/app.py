from flask import Flask, jsonify, render_template_string
from flask_cors import CORS
import threading, time, platform, sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, get_if_list
from collections import defaultdict, Counter
import psutil
import os

app = Flask(__name__)

# enable CORS for frontend
CORS(app, origins=["http://localhost:3000"])

events = []   # simple in-memory log
sniffer_running = False
sniffer_error = None
current_os = platform.system()

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

def check_admin_privileges():
    '''Check if the script is running with admin/root privileges'''
    if current_os == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0
    
def get_interface():
    '''Get the netwrok interface for different os'''
    try:
        interfaces = get_if_list()
        print(f"Available interfaces: {interfaces}")

        for iface in ['en0', 'en1', 'wlan0', 'eth0']:
            if iface in interfaces:
                try:
                    net_stats = psutil.net_if_stats()
                    if iface in net_stats and net_stats[iface].isup:
                        print(f"Using interface: {iface}")
                        return iface
                except:
                    continue
        
        # fallback to first active interface
        for iface in interfaces:
            if not iface.startswith(('lo', 'Loopback')):
                if iface in net_stats and net_stats[iface].isup:
                    print(f"Using fallback interface: {iface}")
                    return iface
        return None
    except Exception as e:      
        print(f"Error getting interfaces: {e}")
        return None         
        # get network interface stats
        # net_stats = psutil.net_if_stats()
        # net_io = psutil.net_if_addrs()

        # Platform specific defaults
        # if current_os == "Windows":
        #     priority_list = ['Ethernet', 'Wi-Fi', 'Local Area Connection', 'Wireless Network Connection', 'Intel']
        # elif current_os == "Darwin":
        #     priority_list = ['en0', 'en1', 'en2', 'en3']
        # else:
        #     priority_list = ['eth0', 'wlan0', 'ens', 'enp', 'wlp']

        # 

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
        print(f"Error processing packet: {e}")

def start_sniffer():
    try:

        if not check_admin_privileges():
            print("Error: This script requires administrative/root privileges to run.")
            return
        interface = get_interface()
        if not interface:
            sniffer_error = "No suitable network interface found or interface is down."
            print(f"Error: {sniffer_error}")
            return

        print(f"Starting packet capture on interface: {interface}")
        sniffer_running = True
        sniffer_error = None

        sniff(iface=interface, prn=packet_handler, store=False)
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

@app.route("/health")
def health_check():
    return jsonify({
        'status': 'ok',
        'sniffer_running': True,
        'timestamp': time.time()
    })

if __name__ == "__main__":
    print("=== Network Packet Analyzer ===")
    print(f"Running as user ID: {os.geteuid()}")
    
    # Show available interfaces
    try:
        interfaces = get_if_list()
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
    except Exception as e:
        print(f"Could not list interfaces: {e}")


    # run sniffer in background thread
    print("Starting sniffer...")
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()

    print("Starting Flask server on http://localhost:8000")
    print("Make sure to run the React frontend separately on http://localhost:3000")
    app.run(host="0.0.0.0", port=8000, debug=True)
