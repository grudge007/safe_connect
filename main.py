#!/usr/bin/python3
"""
Docstring for main snippet
"""

import time
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

CONN_RECORD_FILE = os.getenv("CONN_RECORD_FILE")
ABUSEIP_INFO_FILE = os.getenv("ABUSEIP_INFO_FILE")

ABUSEAPI = os.getenv('ABUSEAPI')
ABUSE_URL = os.getenv('ABUSE_URL')
# abuseip
abuseip_headers = {
    "Accept": "application/json",
    "Key": ABUSEAPI
}


def check_risk_level(abuse_score) -> str:
    """
    Docstring for check_risk_level
    
    :param abuse_score: Description
    :return: Description
    :rtype: str
    """
    if abuse_score <= 15:
        return "SAFE"
    elif abuse_score <= 49:
        return "SUSPICIOUS"
    elif abuse_score >= 50:
        return "MALICIOUS"
    else:
        return "UNKNOWN"



# print(check_risk_level(0, "102.1.1.1"))
while True:
    remote_ips = {}
    virustotal_info = {}
    abuseip_info = {}
    with open (CONN_RECORD_FILE, 'r', encoding="utf-8") as f:
        remote_ips = json.load(f)

    for ip in remote_ips:
        if not remote_ips[ip]["is_checked"]:
            # abuse ip next
            params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
            }
            abuseip_response = requests.get(
                ABUSE_URL, headers=abuseip_headers, params=params, timeout=30
            )
            if abuseip_response.status_code == 200:
                abuseip_data = abuseip_response.json()["data"]
                abuseip_info[ip] = {
                    "IP_Address": ip,
                    "abuseConfidenceScore": abuseip_data["abuseConfidenceScore"],
                    "Country": abuseip_data["countryCode"] 
                }

            if abuseip_data["abuseConfidenceScore"] is None:
                risk_level = "UNKNOWN"
            else:
                risk_level = check_risk_level(abuseip_data["abuseConfidenceScore"])
            print(f'{ip} : {risk_level}')

            remote_ips[ip]["is_checked"] = True
            time.sleep(2)

    with open (ABUSEIP_INFO_FILE, "w", encoding="utf-8") as abuseip_file:
        json.dump(abuseip_info, abuseip_file, indent=2)

    with open(CONN_RECORD_FILE, "w", encoding="utf-8") as conn_file:
        json.dump(remote_ips, conn_file, indent=2)
    time.sleep(3600)
