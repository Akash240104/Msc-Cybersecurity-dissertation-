#!/usr/bin/env python3
import urllib.request
import json
import datetime

API_KEY = "YOUR_API_KEY_HERE"
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-6"

alert = {
    "src_ip": "172.18.0.1",
    "endpoint": "/community/api/v2/community/posts/recent",
    "count": "12",
    "method": "GET",
    "status_code": "200",
    "time": "03:52am",
    "attack": "BOLA - Broken Object Level Authorisation"
}

prompt = f"""You are a SOC Tier 1 analyst. Analyse this alert:
- IP: {alert['src_ip']}
- Endpoint: {alert['endpoint']}
- Requests: {alert['count']} times
- Response: {alert['status_code']}
- Suspected: {alert['attack']}

Provide:
1. SEVERITY: Critical/High/Medium/Low
2. ATTACK_TYPE: 
3. CONFIDENCE: %
4. IMMEDIATE_ACTION:
5. ESCALATE: Yes/No
6. FALSE_POSITIVE: High/Medium/Low
7. REASONING:"""

body = json.dumps({
    "model": MODEL,
    "max_tokens": 500,
    "messages": [{"role": "user", "content": prompt}]
}).encode('utf-8')

req = urllib.request.Request(
    API_URL,
    data=body,
    headers={
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01"
    },
    method="POST"
)

print("Sending alert to Claude AI...")
with urllib.request.urlopen(req) as response:
    result = json.loads(response.read().decode('utf-8'))
    triage = result['content'][0]['text']

print("\nLLM TRIAGE RESULT:")
print("-" * 40)
print(triage)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"../experiments/triage_{timestamp}.txt"
with open(filename, 'w') as f:
    f.write(f"Timestamp: {timestamp}\n")
    f.write(f"Alert: {json.dumps(alert)}\n")
    f.write(f"Triage:\n{triage}")

print(f"\nSaved to: {filename}")
