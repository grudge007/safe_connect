from flask import Flask, render_template, jsonify
import json
import os
from collections import defaultdict

app = Flask(__name__)

CONN_FILE = "connections.json"
ABUSE_FILE = "abuseip.json"
VT_FILE = "vt.json"

def load_data():
    try:
        with open(CONN_FILE, 'r') as f:
            connections = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        connections = {}

    try:
        with open(ABUSE_FILE, 'r') as f:
            abuse_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        abuse_data = {}

    try:
        with open(VT_FILE, 'r') as f:
            vt_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        vt_data = {}

    merged_data = []
    high_risk_count = 0
    countries = set()

    for ip, conn_info in connections.items():
        # Base info
        entry = {
            "ip": ip,
            "remote_port": conn_info.get("remote_port"),
            "local_ip": conn_info.get("local_ip"),
            "local_port": conn_info.get("local_port"),
            "pid": conn_info.get("pid"),
            "country": "Unknown",
            "asn": None,
            "abuse_score": None,
            "vt_stats": None
        }

        # Enrich with AbuseIPDB data
        if ip in abuse_data:
            a_info = abuse_data[ip]
            entry["abuse_score"] = a_info.get("abuseConfidenceScore")
            entry["country"] = a_info.get("Country", entry["country"])
            
            if entry["abuse_score"] and entry["abuse_score"] > 20:
                 high_risk_count += 1

        # Enrich with VirusTotal data
        if ip in vt_data:
            v_info = vt_data[ip]
            entry["asn"] = v_info.get("ASN")
            # Prefer VT country if AbuseIP didn't have it
            if entry["country"] == "Unknown":
                entry["country"] = v_info.get("Country", "Unknown")
            
            entry["vt_stats"] = v_info.get("Last Analysis Stats")
            
            if entry["vt_stats"]:
                if entry["vt_stats"].get("malicious", 0) > 0 or entry["vt_stats"].get("suspicious", 0) > 0:
                     # Avoid double counting if already flagged by AbuseIP
                     if not (entry["abuse_score"] and entry["abuse_score"] > 20):
                        high_risk_count += 1

        if entry["country"] != "Unknown":
            countries.add(entry["country"])

        merged_data.append(entry)

    return merged_data, high_risk_count, len(countries)

@app.route('/')
def index():
    connections, high_risk_count, unique_countries_count = load_data()
    return render_template(
        'index.html', 
        connections=connections, 
        high_risk_count=high_risk_count, 
        unique_countries=unique_countries_count
    )

@app.route('/api/data')
def api_data():
    connections, high_risk, countries = load_data()
    return jsonify({
        "connections": connections,
        "high_risk_count": high_risk,
        "unique_countries": countries
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
