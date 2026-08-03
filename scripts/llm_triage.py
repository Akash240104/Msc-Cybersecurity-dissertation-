#!/usr/bin/env python3
import subprocess
import json
import datetime

def triage_alert(alert):
    prompt = "You are a SOC Tier 1 analyst. Analyse this alert:\n"
    prompt += "IP: " + alert['src_ip'] + "\n"
    prompt += "Attack: " + alert['attack'] + "\n"
    prompt += "Count: " + alert['count'] + "\n"
    prompt += "Provide: 1.SEVERITY 2.ATTACK_TYPE 3.CONFIDENCE 4.ACTION 5.ESCALATE 6.FALSE_POSITIVE 7.REASONING"
    result = subprocess.run(["ollama", "run", "llama3.2", prompt], capture_output=True, text=True)
    return result.stdout

alert = {
    "src_ip": "172.18.0.1",
    "endpoint": "/community/api/v2/community/posts/recent",
    "count": "230 BOLA + 87 Brute Force",
    "method": "GET",
    "status_code": "200",
    "attack": "BOLA and Brute Force detected simultaneously"
}

print("MSc Dissertation - LLM Alert Triage")
print("Analysing alert from: " + alert['src_ip'])
print("Sending to Llama AI...")

triage = triage_alert(alert)
print("\nLLM TRIAGE RESULT:")
print(triage)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
filename = "../experiments/triage_" + timestamp + ".txt"
with open(filename, 'w') as f:
    f.write("Timestamp: " + timestamp + "\n")
    f.write("Alert: " + json.dumps(alert) + "\n")
    f.write("Triage:\n" + triage)

print("Saved to: " + filename)
