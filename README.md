# Safe Connect

Safe Connect is a network monitoring and security analysis tool designed to track established TCP connections and evaluate the risk level of remote IP addresses. By leveraging abuse databases, it identifies potential threats and maintains a historical record of connection activities.

## Features

- **Real-time Connection Monitoring**: Continuously scans for established TCP connections to detect active communication.
- **Risk Assessment**: Automatically checks remote IPs against abuse databases to determine their confidence score and risk level (Safe, Suspicious, or Malicious).
- **History Tracking**: SQL-less persistence using JSON files to store first-seen, last-seen, and risk level data for each IP.
- **Automated Rescanning**: Periodically re-evaluates IPs based on a configurable interval to ensure risk statuses are up-to-date.
- **Reverse DNS Lookup**: Resolves hostnames for connected IPs to provide better context.

## Prerequisites

- **Python 3.x**
- **Libraries**:
  - `psutil` (for network connection monitoring)
  - `python-dotenv` (for environment configuration)
  - `requests` (for API calls)
  - `Flask`
To install the required libraries, you can run:
```bash
pip install psutil python-dotenv requests
```

## Configuration

 The application uses a `.env` file for configuration. Ensure the following variables are set:

- **File Paths**:
  - `CONN_RECORD_FILE`: Path to the JSON file storing current connection records.
  - `ABUSEIP_INFO_FILE`: Path to the JSON file storing detailed abuse info.
  - `HISTORY_FILE`: Path to the JSON file storing historical data.

- **API Configuration**:
  - `ABUSEAPI`: Your API key for the abuse database provider.
  - `ABUSE_URL`: The endpoint URL for the abuse database API.

- **Thresholds & Intervals**:
  - `SAFE_THRESHOLD`: Abuse score below which an IP is considered safe.
  - `MALICIOUS_THRESHOLD`: Abuse score above which an IP is considered malicious.
  - `RESCAN_INTERVAL`: Time in seconds before an IP is re-scanned.

## Usage
###  Analysis Service
Monitors the recorded connections, performs risk analysis, and updates the history.
```bash
python3 main.py
```


## Project Structure

- **`connections.py`**: The core monitoring script that uses `psutil` to fetch active TCP connections.
- **`main.py`**: The deeper analysis engine that processes IPs found by `connections.py`, checks them against the abuse API, and manages the history.
- **`utils.py`**: Contains helper functions for API interaction (`check_abuse_score`), risk classification, and data formatting.
- **`*.json`**: various JSON files (`connections.json`, `history.json`, `abuseip.json`) serve as the database for the application.
