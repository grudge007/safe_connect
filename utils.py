"""
Docstring for utils
"""

import os
import socket
from datetime import datetime
from dotenv import load_dotenv
import requests

load_dotenv()

CONN_RECORD_FILE = os.getenv("CONN_RECORD_FILE")
ABUSEIP_INFO_FILE = os.getenv("ABUSEIP_INFO_FILE")
HISTORY_FILE = os.getenv('HISTORY_FILE')

ABUSEAPI = os.getenv('ABUSEAPI')
ABUSE_URL = os.getenv('ABUSE_URL')

SAFE_THRESHOLD = int(os.getenv('SAFE_THRESHOLD'))
MALICIOUS_THRESHOLD = int(os.getenv('MALICIOUS_THRESHOLD'))
RESCAN_INTERVAL = int(os.getenv('RESCAN_INTERVAL'))

abuseip_info = {}

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


def convert_to_string(timestamp):
    """
    Docstring for convert_to_string
    
    :param timestamp: Description
    """
    # Convert the float timestamp (Unix timestamp) to a datetime object
    dt_object = datetime.fromtimestamp(timestamp)
    # Return the formatted datetime as a string
    return dt_object.strftime("%B %d, %Y %H:%M:%S")


def convert_to_datetime(human_readable_time):
    """
    Docstring for convert_to_datetime
    
    :param human_readable_time: Description
    """
    return datetime.strptime(human_readable_time, "%B %d, %Y %H:%M:%S")



def check_abuse_score(ip_addr):
    """
    Docstring for check_abuse_score
    
    :param ip: Description
    """
    params = {
    "ipAddress": ip_addr,
    "maxAgeInDays": 90
    }

    try:
        abuseip_response = requests.get(
            ABUSE_URL, headers=abuseip_headers, params=params, timeout=30
        )
    except requests.exceptions.Timeout:
        print("The request timed out.")
    except requests.exceptions.ConnectionError:
        print("There was a connection error. Check your internet connection.")
    except requests.exceptions.TooManyRedirects:
        print("Too many redirects. The URL might be wrong.")
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}")

    if abuseip_response.status_code == 200:
        abuseip_data = abuseip_response.json()["data"]
        host_name = reverse_dns_lookup(ip_addr)
        abuseip_info[ip_addr] = {
            "IP_Address": ip_addr,
            "abuseConfidenceScore": abuseip_data["abuseConfidenceScore"],
            "Country": abuseip_data["countryCode"],
            "hostname": host_name
        }

    if abuseip_data["abuseConfidenceScore"] is None:
        risk = "UNKNOWN"
    else:
        risk = check_risk_level(abuseip_data["abuseConfidenceScore"])

    return risk, host_name, abuseip_info


def reverse_dns_lookup(ip_address):
    """
    Performs a reverse DNS lookup for a given IP address.
    """
    try:
        # gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        # Handles the case where the IP address has no associated hostname (no PTR record)
        return "Unknown host"
    except socket.error:
        # Handles other potential socket errors
        return "Unknown host"
