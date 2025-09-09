from flask import Flask, jsonify, render_template_string
import threading, time
from scapy.all import sniff

app = Flask(__name__)

events = []   # simple in-memory log

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

@app.route("/")
def dashboard():
    rows = "".join(
        f"<tr><td>{e['time']}</td><td>{e['src']}</td><td>{e['dst']}</td><td>{e['proto']}</td></tr>"
        for e in reversed(events)
    )
    html = f"""
    <h2>Packet Log</h2>
    <table border="1" cellpadding="4">
      <tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th></tr>
      {rows}
    </table>
    """
    return html

@app.route("/events")
def get_events():
    return jsonify(list(reversed(events[-200:])))

if __name__ == "__main__":
    # run sniffer in background thread
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8000)