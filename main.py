#!/usr/bin/python3
"""
Docstring for main
"""

import requests
import time
import json
import os
from dotenv import load_dotenv

load_dotenv()

CONN_RECORD_FILE = os.getenv("CONN_RECORD_FILE")
VT_INO_FILE = os.getenv("VT_INFO_FILE")
ABUSEIP_INFO_FILE = os.getenv("ABUSEIP_INFO_FILE")

ABUSEAPI = os.getenv('ABUSEAPI')
ABUSE_URL = os.getenv('ABUSE_URL')

VTAPI = os.getenv('VTAPI')
VT_URL = os.getenv('VT_URL')

# virustotal
vt_headers = {
    "x-apikey": VTAPI
}

# abuseip
abuseip_headers = {
    "Accept": "application/json",
    "Key": ABUSEAPI
}




while True:
    remote_ips = {}
    virustotal_info = {}
    abuseip_info = {}
    with open (CONN_RECORD_FILE, 'r', encoding="utf-8") as f:
        remote_ips = json.load(f)

    for ip in remote_ips:
        if not remote_ips[ip]["is_checked"]:
            # virus total first
            vt_url = f"{VT_URL}/{ip}"
            vt_response = requests.get(vt_url, headers=vt_headers, timeout=30)
            if vt_response.status_code == 200:
                vt_json = vt_response.json()
                ip_data = vt_json.get("data", {}).get("attributes", {})
                virustotal_info[ip] = {
                    "IP_Address": ip,
                    "ASN": ip_data.get("asn"),
                    "Country": ip_data.get("country"),
                    "Last Analysis Stats": ip_data.get("last_analysis_stats")
                }

            # abuse ip next
            params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
            }
            abuseip_response = requests.get(ABUSE_URL, headers=abuseip_headers, params=params, timeout=30)
            if abuseip_response.status_code == 200:
                abuseip_data = abuseip_response.json()["data"]
                abuseip_info[ip] = {
                    "IP_Address": ip,
                    "abuseConfidenceScore": abuseip_data["abuseConfidenceScore"],
                    "Country": abuseip_data["countryCode"] 
                }


            remote_ips[ip]["is_checked"] = True
            time.sleep(1)

    with open (VT_INO_FILE, "w", encoding="utf-8") as vt_file:
        json.dump(virustotal_info, vt_file, indent=2)

    with open (ABUSEIP_INFO_FILE, "w", encoding="utf-8") as abuseip_file:
        json.dump(abuseip_info, abuseip_file, indent=2)

    with open(CONN_RECORD_FILE, "w", encoding="utf-8") as conn_file:
        json.dump(remote_ips, conn_file, indent=2)
    
    time.sleep(3600)