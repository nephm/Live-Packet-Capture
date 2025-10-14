from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import threading
import time
import platform
import os
from datetime import datetime
from collections import defaultdict, Counter, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, get_if_list
import psutil

# Setup Flask app
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

# Get system info
CURRENT_OS = platform.system()
HOSTNAME = platform.node()

# Don't capture our own traffic to avoid infinite loops
MONITORING_PORTS = {3000, 5000}
MONITORING_MODE = os.getenv('MONITORING_MODE', 'production')

# Store captured packets (max 10000)
events = deque(maxlen=10000)

# Store security alerts (max 500)
alerts = deque(maxlen=500)

# Track active connections
connections = {}

# Main statistics dictionary
stats = {
    'total_packets': 0,
    'packets_sent': 0,
    'packets_received': 0,
    'filtered_packets': 0,
    'unique_IPs': set(),
    'bytes_sent': 0,
    'bytes_received': 0,
    'protocol_count': defaultdict(int),
    'top_sources': Counter(),
    'top_destinations': Counter(),
    'port_activity': Counter(),
    'packet_sizes': deque(maxlen=1000),
    'bandwidth_history': deque(maxlen=300),
    'start_time': time.time(),
    'last_bandwidth_update': time.time()
}

# Track if sniffer is working
sniffer_state = {
    'running': False,
    'interface': None,
    'error': None,
    'packets_dropped': 0
}

# Security rules - when to create alerts
SECURITY_RULES = {
    'port_scan_threshold': 6,
    'suspicious_ports': [1234, 4444, 5555, 6666, 8080, 31337],
    'large_packet_threshold': 1200,
    'connection_rate_limit': 20,
    'failed_connection_threshold': 5
}

# Keep track of potential attacks
port_scan_tracker = defaultdict(set)
connection_rate_tracker = defaultdict(list)
failed_connection_tracker = defaultdict(int)

# ==================== Helper Functions ====================

def check_admin_privileges():
    """Check if we're running as admin/root (needed for packet capture)"""
    if CURRENT_OS == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def get_network_interface():
    """Find the best network interface to monitor (like WiFi or Ethernet)"""
    try:
        interfaces = get_if_list()
        print(f"[INFO] Found interfaces: {interfaces}")
        
        net_stats = psutil.net_if_stats()
        
        if CURRENT_OS == "Darwin":
            priority_list = ['en0', 'en1', 'en2']
        elif CURRENT_OS == "Windows":
            priority_list = ['Ethernet', 'Wi-Fi', 'Local Area Connection']
        else:
            priority_list = ['eth0', 'wlan0', 'ens', 'enp', 'wlp']
        
        for iface in priority_list:
            if iface in interfaces:
                try:
                    if iface in net_stats and net_stats[iface].isup:
                        print(f"[SUCCESS] Using interface: {iface}")
                        return iface
                except Exception as e:
                    print(f"[WARNING] Couldn't use {iface}: {e}")
                    continue
        
        for iface in interfaces:
            if not iface.startswith(('lo', 'Loopback')):
                try:
                    if iface in net_stats and net_stats[iface].isup:
                        print(f"[INFO] Using backup interface: {iface}")
                        return iface
                except:
                    continue
        
        return None
        
    except Exception as e:
        print(f"[ERROR] Couldn't find network interface: {e}")
        return None

def is_monitoring_traffic(pkt):
    """Check if this packet is from our own app (so we don't monitor ourselves)"""
    if not pkt.haslayer(IP):
        return True
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    if src_ip in ('127.0.0.1', '::1') or dst_ip in ('127.0.0.1', '::1'):
        return True
    
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if sport in MONITORING_PORTS or dport in MONITORING_PORTS:
            return True
    
    if MONITORING_MODE == 'demo':
        return False
    
    return False

def get_protocol_detailed(pkt):
    """Figure out what protocol this packet is using (HTTP, DNS, etc)"""
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        port = min(sport, dport)
        
        match port:
            case 20 | 21: return 'FTP'
            case 22: return 'SSH'
            case 23: return 'TELNET'
            case 25: return 'SMTP'
            case 53: return 'DNS'
            case 80: return 'HTTP'
            case 110: return 'POP3'
            case 143: return 'IMAP'
            case 443: return 'HTTPS'
            case 465: return 'SMTPS'
            case 587: return 'SMTP'
            case 993: return 'IMAPS'
            case 995: return 'POP3S'
            case 3306: return 'MySQL'
            case 3389: return 'RDP'
            case 5432: return 'PostgreSQL'
            case 5900: return 'VNC'
            case 6379: return 'Redis'
            case 8080: return 'HTTP-Alt'
            case _: return 'TCP'
    
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        port = min(sport, dport)
        
        match port:
            case 53: return 'DNS'
            case 67 | 68: return 'DHCP'
            case 123: return 'NTP'
            case 161 | 162: return 'SNMP'
            case 514: return 'SYSLOG'
            case 1194: return 'OpenVPN'
            case _: return 'UDP'
    
    elif pkt.haslayer(ICMP):
        icmp_type = pkt[ICMP].type
        match icmp_type:
            case 0: return 'ICMP Echo Reply'
            case 3: return 'ICMP Dest Unreachable'
            case 8: return 'ICMP Echo Request'
            case 11: return 'ICMP Time Exceeded'
            case _: return 'ICMP'
    
    elif pkt.haslayer(ARP):
        return 'ARP'
    elif pkt.haslayer(DNS):
        return 'DNS'
    else:
        return 'Other'

def get_tcp_flags(pkt):
    """Get TCP flags (SYN, ACK, FIN, etc) - shows connection state"""
    if not pkt.haslayer(TCP):
        return None
    
    flags = []
    tcp_layer = pkt[TCP]
    
    if tcp_layer.flags.S: flags.append('SYN')
    if tcp_layer.flags.A: flags.append('ACK')
    if tcp_layer.flags.F: flags.append('FIN')
    if tcp_layer.flags.R: flags.append('RST')
    if tcp_layer.flags.P: flags.append('PSH')
    if tcp_layer.flags.U: flags.append('URG')
    
    return ','.join(flags) if flags else None

def get_payload_preview(pkt):
    """Get a preview of the packet data (first 50 bytes)"""
    try:
        if pkt.haslayer(TCP) and len(pkt[TCP].payload) > 0:
            payload = bytes(pkt[TCP].payload)[:50]
            return payload.decode('ascii', errors='replace')
        elif pkt.haslayer(UDP) and len(pkt[UDP].payload) > 0:
            payload = bytes(pkt[UDP].payload)[:50]
            return payload.decode('ascii', errors='replace')
    except:
        pass
    return None

def classify_ip_address(ip):
    """Figure out if an IP is private (local network) or public (internet)"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        if ip_obj.is_private:
            return 'Private'
        elif ip_obj.is_loopback:
            return 'Loopback'
        elif ip_obj.is_multicast:
            return 'Multicast'
        elif ip_obj.is_reserved:
            return 'Reserved'
        else:
            return 'Public'
    except:
        return 'Unknown'

def detect_security_threats(event):
    """Look for suspicious activity and create alerts"""
    threats = []
    src_ip = event['src']
    dst_ip = event['dst']
    dport = event['dport']
    protocol = event['protocol']
    size = event['size']
    flags = event.get('flags', '')
    
    # 1. Check for port scanning
    if dport:
        port_scan_tracker[src_ip].add(dport)
        unique_ports = len(port_scan_tracker[src_ip])
        
        if unique_ports > SECURITY_RULES['port_scan_threshold']:
            threats.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'message': f'Possible port scan from {src_ip} - hit {unique_ports} different ports',
                'timestamp': event['time'],
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })
    
    # 2. Check for connections to suspicious ports
    if dport in SECURITY_RULES['suspicious_ports']:
        threats.append({
            'type': 'SUSPICIOUS_PORT',
            'severity': 'MEDIUM',
            'message': f'Connection to suspicious port {dport} from {src_ip}',
            'timestamp': event['time'],
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
    
    # 3. Check for unusually large packets
    if size > SECURITY_RULES['large_packet_threshold']:
        threats.append({
            'type': 'LARGE_PACKET',
            'severity': 'LOW',
            'message': f'Large packet detected ({size} bytes) from {src_ip}',
            'timestamp': event['time'],
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
    
    # 4. Check for too many connections from one IP
    current_time = time.time()
    connection_rate_tracker[src_ip].append(current_time)
    
    connection_rate_tracker[src_ip] = [
        t for t in connection_rate_tracker[src_ip] 
        if current_time - t < 1.0
    ]
    
    if len(connection_rate_tracker[src_ip]) > SECURITY_RULES['connection_rate_limit']:
        threats.append({
            'type': 'HIGH_CONNECTION_RATE',
            'severity': 'HIGH',
            'message': f'Too many connections from {src_ip} - {len(connection_rate_tracker[src_ip])}/sec',
            'timestamp': event['time'],
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
    
    # 5. Check for failed connection attempts
    if flags and 'RST' in flags:
        failed_connection_tracker[src_ip] += 1
        
        if failed_connection_tracker[src_ip] > SECURITY_RULES['failed_connection_threshold']:
            threats.append({
                'type': 'FAILED_CONNECTIONS',
                'severity': 'MEDIUM',
                'message': f'Multiple failed connections from {src_ip} - {failed_connection_tracker[src_ip]} attempts',
                'timestamp': event['time'],
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })
    
    # 6. Check for DNS over TCP (unusual, could be tunneling)
    if protocol == 'DNS' and 'TCP' in str(flags):
        threats.append({
            'type': 'DNS_OVER_TCP',
            'severity': 'LOW',
            'message': f'DNS query over TCP from {src_ip} (unusual behavior)',
            'timestamp': event['time'],
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })
    
    return threats

def track_tcp_connection(pkt, event):
    """Keep track of TCP connections and their states"""
    if not pkt.haslayer(TCP):
        return
    
    flags = event.get('flags', '')
    if not flags:
        return
    
    conn_id = f"{event['src']}:{event['sport']}-{event['dst']}:{event['dport']}"
    
    if 'SYN' in flags and 'ACK' not in flags:
        connections[conn_id] = {
            'state': 'SYN_SENT',
            'start_time': time.time(),
            'packets': 1,
            'bytes_sent': event['size'],
            'last_seen': time.time()
        }
    
    elif conn_id in connections:
        conn = connections[conn_id]
        conn['packets'] += 1
        conn['bytes_sent'] += event['size']
        conn['last_seen'] = time.time()
        
        if 'SYN' in flags and 'ACK' in flags:
            conn['state'] = 'SYN_ACK_RECEIVED'
        elif 'FIN' in flags:
            conn['state'] = 'FIN_SENT'
        elif 'RST' in flags:
            conn['state'] = 'RESET'
            conn['duration'] = time.time() - conn['start_time']

def update_bandwidth_metrics():
    """Update bandwidth stats every second for graphing"""
    current_time = time.time()
    
    if current_time - stats['last_bandwidth_update'] >= 1.0:
        total_bytes = stats['bytes_sent'] + stats['bytes_received']
        
        stats['bandwidth_history'].append({
            'timestamp': current_time,
            'bytes_sent': stats['bytes_sent'],
            'bytes_received': stats['bytes_received'],
            'total_bytes': total_bytes,
            'packets': stats['total_packets']
        })
        
        stats['last_bandwidth_update'] = current_time

def get_ports(pkt):
    """Get the source and destination port numbers"""
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None

# ==================== Main Packet Processing ====================

def packet_handler(pkt):
    """This function is called for every packet we capture"""
    try:
        if is_monitoring_traffic(pkt):
            stats['filtered_packets'] += 1
            return
        
        if not pkt.haslayer(IP):
            return
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet_size = len(pkt)
        protocol = get_protocol_detailed(pkt)
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        sport, dport = get_ports(pkt)
        flags = get_tcp_flags(pkt)
        payload = get_payload_preview(pkt)
        
        src_type = classify_ip_address(src_ip)
        dst_type = classify_ip_address(dst_ip)
        
        stats['total_packets'] += 1
        stats['unique_IPs'].update([src_ip, dst_ip])
        stats['protocol_count'][protocol] += 1
        stats['top_sources'][src_ip] += 1
        stats['top_destinations'][dst_ip] += 1
        stats['packet_sizes'].append(packet_size)
        
        if sport:
            stats['port_activity'][sport] += 1
        if dport:
            stats['port_activity'][dport] += 1
        
        if src_ip.startswith(('192.168.', '10.', '172.')):
            stats['packets_sent'] += 1
            stats['bytes_sent'] += packet_size
        else:
            stats['packets_received'] += 1
            stats['bytes_received'] += packet_size
        
        event = {
            'time': timestamp,
            'src': src_ip,
            'dst': dst_ip,
            'sport': sport,
            'dport': dport,
            'protocol': protocol,
            'size': packet_size,
            'flags': flags,
            'payload_preview': payload,
            'src_type': src_type,
            'dst_type': dst_type,
            'ttl': pkt[IP].ttl if pkt.haslayer(IP) else None
        }
        
        events.append(event)
        
        threats = detect_security_threats(event)
        for threat in threats:
            alerts.append(threat)
        
        track_tcp_connection(pkt, event)
        update_bandwidth_metrics()
        
    except Exception as e:
        if MONITORING_MODE == 'development':
            print(f"[ERROR] Problem processing packet: {e}")

def start_packet_sniffer():
    """Start capturing packets (runs in background)"""
    global sniffer_state
    
    try:
        if not check_admin_privileges():
            error_msg = "Need admin/root privileges to capture packets!"
            print(f"[ERROR] {error_msg}")
            print("[HINT] Try running with 'sudo python3 sniffer.py'")
            sniffer_state['error'] = error_msg
            sniffer_state['running'] = False
            return
        
        interface = get_network_interface()
        if not interface:
            error_msg = "Couldn't find a network interface to monitor"
            print(f"[ERROR] {error_msg}")
            sniffer_state['error'] = error_msg
            sniffer_state['running'] = False
            return
        
        sniffer_state['interface'] = interface
        sniffer_state['running'] = True
        sniffer_state['error'] = None
        
        print(f"[SUCCESS] Starting packet capture on: {interface}")
        print(f"[INFO] Mode: {MONITORING_MODE}")
        print(f"[INFO] Ignoring traffic on ports: {MONITORING_PORTS}")
        
        bpf_filter = "not port 3000 and not port 5000"
        
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            filter=bpf_filter
        )
        
    except PermissionError:
        error_msg = "Permission denied - need to run as admin/root"
        print(f"[ERROR] {error_msg}")
        sniffer_state['error'] = error_msg
        sniffer_state['running'] = False
        
    except Exception as e:
        error_msg = f"Sniffer crashed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        sniffer_state['error'] = error_msg
        sniffer_state['running'] = False

# ==================== API Endpoints ====================

@app.route("/api/events")
def get_events():
    """Get list of captured packets (can filter by protocol or IP)"""
    try:
        limit = int(request.args.get('limit', 200))
        protocol_filter = request.args.get('protocol', '').upper()
        ip_filter = request.args.get('ip', '')
        
        filtered_events = list(events)
        
        if protocol_filter:
            filtered_events = [
                e for e in filtered_events 
                if e['protocol'].upper() == protocol_filter
            ]
        
        if ip_filter:
            filtered_events = [
                e for e in filtered_events 
                if ip_filter in e['src'] or ip_filter in e['dst']
            ]
        
        return jsonify(list(reversed(filtered_events[-limit:])))
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/stats")
def get_statistics():
    """Get overall network statistics"""
    try:
        uptime = int(time.time() - stats['start_time'])
        
        if stats['packet_sizes']:
            avg_size = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
            min_size = min(stats['packet_sizes'])
            max_size = max(stats['packet_sizes'])
        else:
            avg_size = min_size = max_size = 0
        
        return jsonify({
            'total_packets': stats['total_packets'],
            'packets_sent': stats['packets_sent'],
            'packets_received': stats['packets_received'],
            'filtered_packets': stats['filtered_packets'],
            'unique_ips': len(stats['unique_IPs']),
            'bytes_sent': stats['bytes_sent'],
            'bytes_received': stats['bytes_received'],
            'protocol_breakdown': dict(stats['protocol_count']),
            'top_sources': stats['top_sources'].most_common(10),
            'top_destinations': stats['top_destinations'].most_common(10),
            'top_ports': stats['port_activity'].most_common(20),
            'uptime_seconds': uptime,
            'packets_per_second': round(stats['total_packets'] / max(uptime, 1), 2),
            'avg_packet_size': round(avg_size, 2),
            'min_packet_size': min_size,
            'max_packet_size': max_size,
            'active_connections': len([c for c in connections.values() if c.get('state') not in ['RESET', 'FIN_SENT']]),
            'total_alerts': len(alerts)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/alerts")
def get_security_alerts():
    """Get security alerts (can filter by severity)"""
    try:
        severity_filter = request.args.get('severity', '').upper()
        limit = int(request.args.get('limit', 100))
        
        filtered_alerts = list(alerts)
        
        if severity_filter:
            filtered_alerts = [
                a for a in filtered_alerts 
                if a['severity'].upper() == severity_filter
            ]
        
        return jsonify(list(reversed(filtered_alerts[-limit:])))
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/bandwidth")
def get_bandwidth_history():
    """Get bandwidth usage over time (for graphs)"""
    try:
        return jsonify(list(stats['bandwidth_history']))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/connections")
def get_active_connections():
    """Get currently active TCP connections"""
    try:
        active_conns = []
        current_time = time.time()
        
        for conn_id, conn_data in connections.items():
            if current_time - conn_data.get('last_seen', 0) < 60:
                src_dst = conn_id.split('-')
                active_conns.append({
                    'connection_id': conn_id,
                    'source': src_dst[0],
                    'destination': src_dst[1],
                    'state': conn_data.get('state', 'UNKNOWN'),
                    'duration': round(current_time - conn_data['start_time'], 2),
                    'packets': conn_data.get('packets', 0),
                    'bytes': conn_data.get('bytes_sent', 0)
                })
        
        return jsonify(active_conns)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/protocols")
def get_protocol_breakdown():
    """Get breakdown of which protocols we're seeing"""
    try:
        return jsonify(dict(stats['protocol_count']))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/export")
def export_capture_data():
    """Export everything as JSON for later analysis"""
    try:
        export_data = {
            'metadata': {
                'export_time': datetime.now().isoformat(),
                'hostname': HOSTNAME,
                'interface': sniffer_state.get('interface'),
                'monitoring_mode': MONITORING_MODE,
                'uptime_seconds': int(time.time() - stats['start_time'])
            },
            'statistics': {
                'total_packets': stats['total_packets'],
                'packets_sent': stats['packets_sent'],
                'packets_received': stats['packets_received'],
                'unique_ips': len(stats['unique_IPs']),
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'protocol_count': dict(stats['protocol_count'])
            },
            'events': list(events),
            'alerts': list(alerts),
            'bandwidth_history': list(stats['bandwidth_history']),
            'active_connections': len([c for c in connections.values() if c.get('state') not in ['RESET', 'FIN_SENT']])
        }
        
        return jsonify(export_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/export_csv")
def export_capture_csv():
    try:
        limit = request.args.get('limit', default=None, type=int)
        rows = list(events)
        if limit is not None and limit > 0:
            rows = rows[-limit:]
        rows = list(reversed(rows))

        headers = [
            'time', 'src', 'dst', 'protocol', 'sport', 'dport', 'size',
            'flags', 'payload_preview', 'src_type', 'dst_type', 'ttl'
        ]

        def generate():
            yield ','.join(headers) + '\n'
            for e in rows:
                def esc(v):
                    if v is None:
                        return ''
                    s = str(v)
                    if any(ch in s for ch in [',', '\n', '"']):
                        s = '"' + s.replace('"', '""') + '"'
                    return s
                yield ','.join([
                    esc(e.get('time')),
                    esc(e.get('src')),
                    esc(e.get('dst')),
                    esc(e.get('protocol')),
                    esc(e.get('sport')),
                    esc(e.get('dport')),
                    esc(e.get('size')),
                    esc(e.get('flags')),
                    esc(e.get('payload_preview')),
                    esc(e.get('src_type')),
                    esc(e.get('dst_type')),
                    esc(e.get('ttl')),
                ]) + '\n'

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"packets_{timestamp}.csv"
        return Response(generate(), mimetype='text/csv', headers={
            'Content-Disposition': f'attachment; filename={filename}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/health")
def health_check():
    """Check if everything is working"""
    try:
        return jsonify({
            'status': 'healthy' if sniffer_state['running'] else 'degraded',
            'sniffer_running': sniffer_state['running'],
            'sniffer_error': sniffer_state['error'],
            'interface': sniffer_state.get('interface'),
            'timestamp': time.time(),
            'uptime_seconds': int(time.time() - stats['start_time']),
            'total_packets_captured': stats['total_packets']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/")
def index():
    """Welcome page - shows available API endpoints"""
    return jsonify({
        'name': 'Network Packet Sniffer API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'GET /api/events': 'Get captured packets',
            'GET /api/stats': 'Get network statistics',
            'GET /api/alerts': 'Get security alerts',
            'GET /api/bandwidth': 'Get bandwidth history',
            'GET /api/connections': 'Get active connections',
            'GET /api/protocols': 'Get protocol breakdown',
            'GET /api/export': 'Export all data as JSON',
            'GET /api/health': 'Check if sniffer is running'
        }
    })

# ==================== Main Program ====================

if __name__ == "__main__":
    print("=" * 60)
    print("Network Packet Sniffer - Starting Up")
    print("=" * 60)
    print(f"OS: {CURRENT_OS}")
    print(f"Hostname: {HOSTNAME}")
    
    if not check_admin_privileges():
        print("\n[WARNING] Not running with admin privileges!")
        print("[INFO] Packet capture requires root/admin access")
        if CURRENT_OS == "Windows":
            print("[HINT] Right-click and 'Run as Administrator'")
        else:
            print("[HINT] Run with: sudo python3 sniffer.py")
    
    try:
        interfaces = get_if_list()
        print(f"\nFound {len(interfaces)} network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
    except Exception as e:
        print(f"Couldn't list interfaces: {e}")
    
    print("\n" + "=" * 60)
    print("Starting packet capture thread...")
    print("=" * 60)
    
    sniffer_thread = threading.Thread(target=start_packet_sniffer, daemon=True)
    sniffer_thread.start()
    
    time.sleep(2)
    
    if sniffer_state['running']:
        print(f"[SUCCESS] Sniffer is running on interface: {sniffer_state['interface']}")
    else:
        print(f"[ERROR] Sniffer failed to start: {sniffer_state['error']}")
    
    print("\n" + "=" * 60)
    print("Starting Flask web server...")
    print("=" * 60)
    print("Server: http://localhost:8000")
    print("\nAvailable endpoints:")
    print("  - http://localhost:8000/api/events")
    print("  - http://localhost:8000/api/stats")
    print("  - http://localhost:8000/api/alerts")
    print("  - http://localhost:8000/api/bandwidth")
    print("  - http://localhost:8000/api/health")
    print("\nPress Ctrl+C to stop")
    print("=" * 60 + "\n")
    
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)