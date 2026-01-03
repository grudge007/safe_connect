#!/usr/bin/python3
"""
Docstring for main snippet
"""
import time
import json
import os
# import signal
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from utils import check_abuse_score, convert_to_datetime, convert_to_string, atomic_write


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

load_dotenv()

CONN_RECORD_FILE = os.getenv("CONN_RECORD_FILE")
ABUSEIP_INFO_FILE = os.getenv("ABUSEIP_INFO_FILE")
HISTORY_FILE = os.getenv('HISTORY_FILE')
RESCAN_INTERVAL = int(os.getenv('RESCAN_INTERVAL'))

if not os.path.exists(CONN_RECORD_FILE):
    with open (CONN_RECORD_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f, indent=2)

if not os.path.exists(HISTORY_FILE):
    with open (HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f, indent=2)

if not os.path.exists(ABUSEIP_INFO_FILE):
    with open (ABUSEIP_INFO_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f, indent=2)

# signal.signal(signal.SIGINT, graceful_shutdown)  # Handle Ctrl+C (SIGINT)
# signal.signal(signal.SIGTERM, graceful_shutdown)  # Handle termination request (SIGTERM)


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
                        logger.info(f"IP {ip} was already seen {history[ip]['times_seen']} times")
                        time_diff = datetime.now() - convert_to_datetime(history[ip]['last_seen'])

                        if time_diff > timedelta(seconds=RESCAN_INTERVAL):
                            logger.info(f"Time difference for {ip}: {time_diff}")
                            risk_level = check_abuse_score(ip)
                            history[ip]['risk_level'] = risk_level
                            history[ip]['last_seen'] = convert_to_string(time.time())
                            history[ip]['last_scanned'] = convert_to_string(time.time())
                            logger.info(f"Rescanned IP {ip} with risk level: {risk_level}")
                            continue
                        remote_ips[ip]["is_checked"] = True
                        history[ip]['last_seen'] = convert_to_string(time.time())
                        logger.info(f"Updated last seen time for IP {ip}")
                        continue

                    except KeyError:
                        pass
            except KeyError:
                pass

            logger.info(f"Processing new IP: {ip}")
            risk_level, HOSTNAME, abuseip_info = check_abuse_score(ip)
            history[ip] = {
                "first_seen": convert_to_string(time.time()),
                "last_seen": convert_to_string(time.time()),
                "times_seen": 1,
                "risk_level": risk_level,
                "last_scanned": convert_to_string(time.time())
            }

            remote_ips[ip]["is_checked"] = True
            logger.info(f"New IP {ip} added with risk level: {risk_level}")

            time.sleep(2)

        elif remote_ips[ip]["is_checked"]:
            try:
                history[ip]['last_seen'] = convert_to_string(time.time())
                with open (HISTORY_FILE, "w", encoding="utf-8") as history_file:
                    json.dump(history, history_file, indent=2)
                continue
            except KeyError:
                continue

    with open (ABUSEIP_INFO_FILE, "r", encoding="utf-8") as abuseip_file:
        existing_data = json.load(abuseip_file)

    merged_data = {**existing_data, **abuseip_info}
    atomic_write(ABUSEIP_INFO_FILE, merged_data)

    # with open (ABUSEIP_INFO_FILE, "w", encoding="utf-8") as abuseip_file:
    #     json.dump(merged_data, abuseip_file, indent=2)
    atomic_write(CONN_RECORD_FILE, remote_ips)
    # with open(CONN_RECORD_FILE, "w", encoding="utf-8") as conn_file:
    #     json.dump(remote_ips, conn_file, indent=2)

    # with open (HISTORY_FILE, "w", encoding="utf-8") as history_file:
    #     json.dump(history, history_file, indent=2)
    atomic_write(HISTORY_FILE, history)

    logger.info("Completed processing cycle, sleeping for 30 minutes")
    time.sleep(1800)
