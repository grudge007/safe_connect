"""
Docstring for connections
"""
import os
import json
import time
import psutil
from dotenv import load_dotenv
load_dotenv()
CONN_RECORD_FILE = os.getenv("CONN_RECORD_FILE")
CONN_RECORD = {}

if not os.path.exists(CONN_RECORD_FILE):
    # Create an empty JSON file
    with open(CONN_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f, indent=2)

with open (CONN_RECORD_FILE, 'r', encoding="utf-8") as f:
    remote_ips = json.load(f)    

while True:
    for conn in psutil.net_connections(kind='tcp4'):
        if conn.status == "ESTABLISHED":
            remote_ip = conn.raddr.ip
            if remote_ip.startswith("127."):
                continue

            CONN_RECORD[conn.raddr.ip] = {
                "remote_port" : conn.raddr.port,
                "local_ip" : conn.laddr.ip,
                "local_port" : conn.laddr.port,
                "pid" : conn.pid,
                "is_checked" : remote_ips.get(conn.raddr.ip, {}).get("is_checked", False)
            }
    with open(CONN_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump(CONN_RECORD, f, indent=2)

    time.sleep(300)
