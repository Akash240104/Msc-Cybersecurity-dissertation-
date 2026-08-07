#!/usr/bin/env python3
"""Shared helper — pushes one attack event into Splunk via HTTP Event Collector."""
import os
import requests
import urllib3
urllib3.disable_warnings()

HEC_URL = "https://localhost:8088/services/collector/event"
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN")

def send_to_splunk(raw_event_text, sourcetype="access_combined"):
    if not HEC_TOKEN:
        print("[WARN] SPLUNK_HEC_TOKEN not set - event not sent to Splunk")
        return False
    payload = {"event": raw_event_text, "sourcetype": sourcetype, "index": "api_logs"}
    headers = {"Authorization": "Splunk " + HEC_TOKEN}
    try:
        r = requests.post(HEC_URL, json=payload, headers=headers, verify=False, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print("[ERROR] Splunk push failed: " + str(e))
        return False
