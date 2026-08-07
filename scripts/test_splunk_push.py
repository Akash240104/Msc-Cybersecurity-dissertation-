#!/usr/bin/env python3
import os
import requests
import urllib3
urllib3.disable_warnings()

HEC_URL = "https://localhost:8088/services/collector/event"
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN")

if not HEC_TOKEN:
    print("[ERROR] SPLUNK_HEC_TOKEN not set. Run: export SPLUNK_HEC_TOKEN=\"your-token\"")
    exit(1)

log_line = '172.18.0.1 - - "GET /community/api/v2/community/posts/recent HTTP/1.1" 200'

payload = {"event": log_line, "sourcetype": "access_combined", "index": "api_logs"}
headers = {"Authorization": "Splunk " + HEC_TOKEN}

r = requests.post(HEC_URL, json=payload, headers=headers, verify=False, timeout=5)

print("Status code:", r.status_code)
print("Response:", r.text)
