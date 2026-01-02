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
HISTORY_FILE = os.getenv('HISTORY_FILE')

ABUSEAPI = os.getenv('ABUSEAPI')
ABUSE_URL = os.getenv('ABUSE_URL')

SAFE_THRESHOLD = int(os.getenv('SAFE_THRESHOLD'))
MALICIOUS_THRESHOLD = int(os.getenv('MALICIOUS_THRESHOLD'))
RESCAN_INTERVAL = int(os.getenv('RESCAN_INTERVAL'))
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
    if abuse_score <= SAFE_THRESHOLD:
        return "SAFE"
    if abuse_score < MALICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    if abuse_score >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    return "UNKNOWN"


# def check_abuse_score()

while True:
    remote_ips = {}
    abuseip_info = {}
    history = {}

    with open (CONN_RECORD_FILE, 'r', encoding="utf-8") as connections:
        remote_ips = json.load(connections)

    with open (ABUSEIP_INFO_FILE, 'r', encoding="utf-8") as abuse_ip:
        abuse_ips = json.load(abuse_ip)

    with open(HISTORY_FILE,'r', encoding="utf-8") as history_file:
        history = json.load(history_file)

    for ip in remote_ips:
        if not remote_ips[ip]["is_checked"]:
            try:
                if abuse_ips[ip]:
                    try:
                        history[ip]['times_seen'] += 1
                        print(f"{ip} was alraedy here")
                        if time.time() - history[ip]['last_seen'] > RESCAN_INTERVAL:
                            pass
                        remote_ips[ip]["is_checked"] = True
                        continue
                    except KeyError:
                        pass
            except KeyError:
                pass
            # abuse ip check
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

            history[ip] = {
                "first_seen": time.time(),
                "last_seen": time.time(),
                "times_seen": 1,
                "risk_level": risk_level,
                "last_scanned": time.time()
            }

            remote_ips[ip]["is_checked"] = True

            time.sleep(2)

        elif remote_ips[ip]["is_checked"]:
            try:
                history[ip]['last_seen'] = time.time()
                with open (HISTORY_FILE, "w", encoding="utf-8") as history_file:
                    json.dump(history, history_file, indent=2)
                continue
            except KeyError:
                continue
                


    with open (ABUSEIP_INFO_FILE, "r", encoding="utf-8") as abuseip_file:
        existing_data = json.load(abuseip_file)

    merged_data = {**existing_data, **abuseip_info}

    with open (ABUSEIP_INFO_FILE, "w", encoding="utf-8") as abuseip_file:
        json.dump(merged_data, abuseip_file, indent=2)

    with open(CONN_RECORD_FILE, "w", encoding="utf-8") as conn_file:
        json.dump(remote_ips, conn_file, indent=2)

    with open (HISTORY_FILE, "w", encoding="utf-8") as history_file:
        json.dump(history, history_file, indent=2)

    time.sleep(1800)
