import os
import json
import sys
from flask import Flask, render_template, jsonify
from dotenv import load_dotenv
from utils import is_port_open

# Load environment variables from the parent directory
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

app = Flask(__name__)

# Configuration - using paths from env or defaults relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def resolve_path(env_var, default_filename):
    path = os.getenv(env_var, default_filename)
    if not os.path.isabs(path):
        return os.path.join(BASE_DIR, path)
    return path

CONN_RECORD_FILE = resolve_path("CONN_RECORD_FILE", "connections.json")
ABUSEIP_INFO_FILE = resolve_path("ABUSEIP_INFO_FILE", "abuseip.json")
HISTORY_FILE = resolve_path("HISTORY_FILE", "history.json")

def read_json_safe(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return {}

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/api/data')
def get_data():
    connections = read_json_safe(CONN_RECORD_FILE)
    abuse_info = read_json_safe(ABUSEIP_INFO_FILE)
    history_data = read_json_safe(HISTORY_FILE)

    # Calculate stats
    total_connections = len(connections)
    safe_count = 0
    suspicious_count = 0
    malicious_count = 0
    
    # Process connections to include abuse info
    active_connections_list = []
    
    for ip, conn_details in connections.items():
        # Get risk info from history or default to UNKNOWN
        ip_history = history_data.get(ip, {})
        risk_level = ip_history.get('risk_level', 'UNKNOWN')
        
        # Get abuse details
        ip_abuse = abuse_info.get(ip, {})
        
        # Update counts
        if risk_level == 'SAFE':
            safe_count += 1
        elif risk_level == 'SUSPICIOUS':
            suspicious_count += 1
        elif risk_level == 'MALICIOUS':
            malicious_count += 1

        conn_data = {
            "ip": ip,
            "local_ip": conn_details.get("local_ip", ""),
            "local_port": conn_details.get("local_port", ""),
            "remote_port": conn_details.get("remote_port", ""),
            "pid": conn_details.get("pid", ""),
            "risk_level": risk_level,
            "country": ip_abuse.get("Country", "N/A"),
            "hostname": ip_abuse.get("hostname", "Resolving..."),
            "abuse_score": ip_abuse.get("abuseConfidenceScore", "N/A"),
            "last_scanned": ip_history.get("last_scanned", "Never")
        }
        active_connections_list.append(conn_data)

    stats = {
        "all": total_connections,
        "safe": safe_count,
        "suspicious": suspicious_count,
        "malicious": malicious_count
    }

    return jsonify({
        "stats": stats,
        "connections": active_connections_list
    })

@app.route('/api/history')
def get_history():
    history_data = read_json_safe(HISTORY_FILE)
    abuse_info = read_json_safe(ABUSEIP_INFO_FILE)
    connections = read_json_safe(CONN_RECORD_FILE)
    
    history_list = []
    for ip, details in history_data.items():
        ip_abuse = abuse_info.get(ip, {})
        is_active = ip in connections
        
        item = {
            "ip": ip,
            "first_seen": details.get("first_seen", ""),
            "last_seen": details.get("last_seen", ""),
            "times_seen": details.get("times_seen", 0),
            "risk_level": details.get("risk_level", "UNKNOWN"),
            "hostname": ip_abuse.get("hostname", "N/A"),
            "country": ip_abuse.get("Country", "N/A"),
            "abuse_score": ip_abuse.get("abuseConfidenceScore", "N/A"),
            "is_active": is_active,
            "reason": details.get("reason", None)
        }
        history_list.append(item)
        
    return jsonify(history_list)
# if is_port_open('0.0.0.0', 5000):
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
# else:
#     print(f'Port is already in use or service is running')
#     sys.exit(1)
