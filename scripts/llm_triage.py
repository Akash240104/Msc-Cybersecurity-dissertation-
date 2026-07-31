#!/usr/bin/env python3
import subprocess
import json
import datetime

def triage_alert(alert):
    prompt = f"""You are a SOC Tier 1 analyst. Analyse this security alert:
- Source IP: {alert['src_ip']}
- Endpoint: {alert['endpoint']}
- Request count: {alert['count']} times in 2 minutes
- HTTP Method: {alert['method']}
- Response code: {alert['status_code']}
- Suspected attack: {alert['attack']}

Provide exactly:
1. SEVERITY: Critical/High/Medium/Low
2. ATTACK_TYPE: 
3. CONFIDENCE: %
4. IMMEDIATE_ACTION:
5. ESCALATE: Yes/No
6. FALSE_POSITIVE: High/Medium/Low
7. REASONING:"""

    result = subprocess.run(
        ["ollama", "run", "llama3.2", prompt],
        capture_output=True,
        text=True
    )
    return result.stdout

alert = {
    "src_ip": "172.18.0.1",
    "endpoint": "/community/api/v2/community/posts/recent",
    "count": "12",
    "method": "GET",
    "status_code": "200",
    "attack": "BOLA - Broken Object Level Authorisation"
}

print("=" * 50)
print("MSc Dissertation - LLM Alert Triage")
print("=" * 50)
print(f"Analysing alert from: {alert['src_ip']}")
print("Sending to Llama AI...")
print("-" * 50)

triage = triage_alert(alert)

print("\nLLM TRIAGE RESULT:")
print("-" * 50)
print(triage)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"../experiments/triage_{timestamp}.txt"
with open(filename, 'w') as f:
    f.write("=" * 50 + "\n")
    f.write("LLM ALERT TRIAGE RESULT\n")
    f.write("=" * 50 + "\n")
    f.write(f"Timestamp: {timestamp}\n")
    f.write(f"Model: llama3.2 (Ollama)\n")
    f.write(f"Alert: {json.dumps(alert)}\n\n")
    f.write("TRIAGE OUTPUT:\n")
    f.write("-" * 50 + "\n")
    f.write(triage)

print(f"\nResult saved to: {filename}")
print("Triage complete!")
